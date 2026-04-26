from flask import Flask, jsonify, request, Response, stream_with_context, send_from_directory
import uuid, json, threading, queue, os, re, logging
from datetime import datetime
from sqlalchemy import inspect, text
from scanners import (
    scan_subdomain_takeover,
    scan_s3_buckets,
    scan_cors,
    scan_sensitive_files,
    scan_api_key_leak,
    scan_open_redirect,
    scan_clickjacking,
    scan_dns_zone_transfer,
    scan_spf_dmarc,
    scan_rate_limit,
    scan_nuclei,
    takeover_enumerate,
    takeover_triage,
    takeover_scan_cnames,
    takeover_verify,
    _parse_burp_issue,
)
from db import db, Finding, Scan

# ── App Setup ─────────────────────────────────────────────────────────────────

app = Flask(__name__, static_folder="../dist", static_url_path="")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///bbh.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── Scanner Registry ──────────────────────────────────────────────────────────

SCANNER_MAP = {
    "subdomain-takeover": scan_subdomain_takeover,
    "s3-buckets":         scan_s3_buckets,
    "cors":               scan_cors,
    "sensitive-files":    scan_sensitive_files,
    "api-key-leak":       scan_api_key_leak,
    "open-redirect":      scan_open_redirect,
    "clickjacking":       scan_clickjacking,
    "dns-zone-transfer":  scan_dns_zone_transfer,
    "spf-dmarc":          scan_spf_dmarc,
    "rate-limit":         scan_rate_limit,
    "nuclei":             scan_nuclei,
}

# ── In-memory SSE State ───────────────────────────────────────────────────────

# scan_id → Queue
scan_queues: dict[str, queue.Queue] = {}
# scan_id → created_at datetime
scan_timestamps: dict[str, datetime] = {}
# Lock to protect concurrent access to scan_queues and scan_timestamps
_queue_lock = threading.Lock()

# Global activity SSE queue
activity_queue: queue.Queue = queue.Queue(maxsize=200)

# ── Constants ─────────────────────────────────────────────────────────────────

MAX_TARGET_LENGTH = 2048
MAX_BURP_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
MALICIOUS_PATTERNS = [
    r"<script[^>]*>.*?</script>",
    r"javascript:",
    r"onerror\s*=",
    r"onclick\s*=",
    r"onload\s*=",
]

# ── DB Init ───────────────────────────────────────────────────────────────────

with app.app_context():
    db.create_all()
    inspector = inspect(db.engine)
    if inspector.has_table("findings"):
        existing = {col["name"] for col in inspector.get_columns("findings")}
        if "details" not in existing:
            db.session.execute(text("ALTER TABLE findings ADD COLUMN details TEXT DEFAULT ''"))
        if "vulnerable_objects" not in existing:
            db.session.execute(text("ALTER TABLE findings ADD COLUMN vulnerable_objects TEXT DEFAULT '[]'"))
        db.session.commit()

# ── Helpers ───────────────────────────────────────────────────────────────────

def validate_target(target: str) -> tuple[bool, str]:
    if not target or not isinstance(target, str):
        return False, "Target must be a non-empty string"
    if len(target) > MAX_TARGET_LENGTH:
        return False, f"Target exceeds maximum length of {MAX_TARGET_LENGTH}"
    for pattern in MALICIOUS_PATTERNS:
        if re.search(pattern, target, re.IGNORECASE | re.DOTALL):
            return False, "Target contains suspicious patterns"
    return True, ""


def cleanup_old_scans(max_age_seconds: int = 300):
    """Remove stale scan queues. Thread-safe."""
    now = datetime.utcnow()
    with _queue_lock:
        expired = [
            sid for sid, ts in scan_timestamps.items()
            if (now - ts).total_seconds() > max_age_seconds
        ]
        for sid in expired:
            scan_queues.pop(sid, None)
            scan_timestamps.pop(sid, None)


def _register_scan_queue(scan_id: str) -> queue.Queue:
    q = queue.Queue()
    with _queue_lock:
        scan_queues[scan_id] = q
        scan_timestamps[scan_id] = datetime.utcnow()
    return q


def _deregister_scan_queue(scan_id: str):
    with _queue_lock:
        scan_queues.pop(scan_id, None)
        scan_timestamps.pop(scan_id, None)


def _push_activity(event: dict):
    """Push to global activity SSE queue without blocking."""
    try:
        activity_queue.put_nowait(event)
    except queue.Full:
        pass  # Drop oldest implicitly — maxsize handles it


def _validate_finding_data(data: dict) -> bool:
    try:
        required = ["asset", "finding", "severity", "details", "h1_report"]
        for field in required:
            if not data.get(field) or not isinstance(data.get(field), str):
                return False
        severity = data.get("severity", "").lower()
        if severity not in ["critical", "high", "medium", "low", "info"]:
            return False
        vuln_objs = data.get("vulnerable_objects", "[]")
        if isinstance(vuln_objs, str):
            objs = json.loads(vuln_objs)
            if not isinstance(objs, list):
                return False
        return True
    except Exception:
        return False


def _save_finding(scan_id: str, module: str, data: dict):
    if not _validate_finding_data(data):
        logger.error(f"[SAVE] Invalid finding data for module={module}")
        return
    try:
        with app.app_context():
            f = Finding(
                id=str(uuid.uuid4()),
                scan_id=scan_id,
                module=module,
                asset=str(data.get("asset", "")).strip(),
                finding=str(data.get("finding", "")).strip(),
                severity=str(data.get("severity", "info")).lower(),
                status="new",
                details=str(data.get("details", "")).strip(),
                evidence=json.dumps(
                    json.loads(data.get("evidence", "{}"))
                    if isinstance(data.get("evidence"), str)
                    else data.get("evidence", {})
                ),
                h1_report=str(data.get("h1_report", "")).strip(),
                timestamp=datetime.utcnow(),
            )
            vuln_objs = data.get("vulnerable_objects", "[]")
            f.vulnerable_objects = vuln_objs if isinstance(vuln_objs, str) else json.dumps(vuln_objs)
            db.session.add(f)
            db.session.commit()
            logger.info(f"[SAVE] Finding saved: {f.finding[:60]} ({f.severity})")
    except Exception as e:
        logger.exception(f"[SAVE] Failed: {e}")


def _finding_dict(f: Finding) -> dict:
    return {
        "id": f.id,
        "asset": f.asset,
        "finding": f.finding,
        "severity": f.severity,
        "status": f.status,
        "module": f.module,
        "scan_id": f.scan_id,
        "timestamp": f.timestamp.isoformat() if f.timestamp else None,
        "details": f.details or "",
        "vulnerableObjects": f.get_vulnerable_objects(),
        "evidence": json.loads(f.evidence) if f.evidence else {},
        "h1_report": f.h1_report or "",
    }


def _validate_scan_id(scan_id: str) -> bool:
    try:
        uuid.UUID(scan_id)
        return True
    except (ValueError, AttributeError):
        return False


# ── Background Scanner Runner ─────────────────────────────────────────────────

def _run_scanner(scan_id: str, module_id: str, target: str, options: dict):
    """Run scanner in background thread, push SSE events to queue."""
    q = scan_queues.get(scan_id)
    if not q:
        logger.error(f"[RUNNER] No queue for scan_id={scan_id}")
        return

    scanner = SCANNER_MAP[module_id]
    completed = False

    try:
        for event in scanner(target, options):
            if not isinstance(event, dict):
                continue

            event_type = event.get("type")
            if event_type not in ("log", "finding", "complete"):
                continue

            if event_type == "log":
                msg = event.get("message")
                if not msg or not isinstance(msg, str):
                    continue
                q.put(event)

            elif event_type == "finding":
                data = event.get("data")
                if not isinstance(data, dict):
                    continue
                if not _validate_finding_data(data):
                    logger.warning("[RUNNER] Finding failed validation — dropped")
                    continue
                q.put(event)
                _save_finding(scan_id, module_id, data)
                _push_activity({
                    "type": data.get("severity", "info"),
                    "message": f"[{data.get('severity', 'info').upper()}] {data.get('finding', '')} on {data.get('asset', '')}",
                    "time": datetime.utcnow().isoformat(),
                })

            elif event_type == "complete":
                # Handled in finally
                break

    except Exception as e:
        logger.exception(f"[RUNNER] Scanner {module_id} error: {e}")
        q.put({"type": "log", "message": f"[ERROR] {str(e)}"})
    finally:
        # Always send exactly one complete event
        q.put({"type": "complete"})
        completed = True

        # Update DB
        with app.app_context():
            try:
                s = db.session.get(Scan, scan_id)
                if s:
                    s.status = "complete"
                    s.finished_at = datetime.utcnow()
                    db.session.commit()
            except Exception as e:
                logger.exception(f"[RUNNER] Failed to update scan status: {e}")

        # Deregister queue after short delay (allow SSE stream to drain)
        def _delayed_cleanup():
            import time
            time.sleep(15)
            _deregister_scan_queue(scan_id)

        threading.Thread(target=_delayed_cleanup, daemon=True).start()


# ── Scan Trigger ──────────────────────────────────────────────────────────────

def _start_scan(module_id: str, target: str, options: dict) -> tuple[dict, int]:
    """Shared scan creation logic. Returns (response_dict, http_status)."""
    if module_id not in SCANNER_MAP:
        return {"error": f"Unknown module: {module_id}. Valid: {list(SCANNER_MAP.keys())}"}, 404

    is_valid, error_msg = validate_target(target)
    if not is_valid:
        return {"error": f"Invalid target: {error_msg}"}, 400

    cleanup_old_scans()

    scan_id = str(uuid.uuid4())
    _register_scan_queue(scan_id)

    with app.app_context():
        scan = Scan(
            id=scan_id, module=module_id, target=target,
            status="running", started_at=datetime.utcnow(),
        )
        db.session.add(scan)
        db.session.commit()

    threading.Thread(
        target=_run_scanner,
        args=(scan_id, module_id, target, options),
        daemon=True,
    ).start()

    return {"scan_id": scan_id, "status": "running"}, 200


@app.route("/api/scan/<module>", methods=["POST"])
def trigger_scan(module):
    """Low-level scan trigger by module name."""
    data = request.get_json(silent=True) or {}
    target = str(data.get("target") or "").strip()
    options = data.get("options", {}) if isinstance(data.get("options"), dict) else {}
    if not target:
        return jsonify({"error": "target required"}), 400
    result, status = _start_scan(module, target, options)
    return jsonify(result), status


@app.route("/api/scans/run", methods=["POST"])
def run_scan_api():
    """Frontend-facing unified scan endpoint."""
    data = request.get_json(silent=True) or {}
    module_id = str(data.get("moduleId") or "").strip()
    target = str(data.get("target") or "").strip()
    options = data.get("options", {}) if isinstance(data.get("options"), dict) else {}

    if not module_id or not target:
        return jsonify({"error": "moduleId and target are required"}), 400

    result, status = _start_scan(module_id, target, options)
    return jsonify(result), status


# ── Burp Import ───────────────────────────────────────────────────────────────

@app.route("/api/import/burp", methods=["POST"])
def import_burp_json():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    if not file.filename:
        return jsonify({"error": "No file selected"}), 400

    # File size guard
    file.seek(0, 2)
    size = file.tell()
    file.seek(0)
    if size > MAX_BURP_FILE_SIZE:
        return jsonify({"error": f"File exceeds {MAX_BURP_FILE_SIZE // 1024 // 1024}MB limit"}), 413

    try:
        data = json.load(file)
    except json.JSONDecodeError as e:
        return jsonify({"error": f"Invalid JSON: {e}"}), 400
    except Exception as e:
        return jsonify({"error": f"Error reading file: {e}"}), 400

    if not isinstance(data, list):
        return jsonify({"error": "Expected JSON array of issues"}), 400

    import_scan_id = str(uuid.uuid4())
    with app.app_context():
        scan = Scan(
            id=import_scan_id, module="burp-import", target="[bulk-import]",
            status="complete", started_at=datetime.utcnow(), finished_at=datetime.utcnow(),
        )
        db.session.add(scan)
        db.session.commit()

    imported = 0
    for issue in data:
        f = _parse_burp_issue(issue)
        if f:
            _save_finding(import_scan_id, "burp-import", f)
            imported += 1

    return jsonify({"message": f"Imported {imported} findings", "scan_id": import_scan_id}), 200


# ── SSE Stream ────────────────────────────────────────────────────────────────

@app.route("/api/stream/<scan_id>")
def stream(scan_id):
    if not _validate_scan_id(scan_id):
        return jsonify({"error": "Invalid scan_id"}), 400

    with _queue_lock:
        q = scan_queues.get(scan_id)

    if not q:
        return Response(
            'data: {"type": "complete"}\n\n',
            mimetype="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    def generate():
        while True:
            try:
                event = q.get(timeout=30)
                yield f"data: {json.dumps(event)}\n\n"
                if event.get("type") == "complete":
                    break
            except queue.Empty:
                yield 'data: {"type": "ping"}\n\n'

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/api/stream/activity")
def activity_stream():
    def generate():
        while True:
            try:
                event = activity_queue.get(timeout=30)
                yield f"data: {json.dumps(event)}\n\n"
            except queue.Empty:
                yield 'data: {"type": "ping"}\n\n'

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache"},
    )


# ── Results ───────────────────────────────────────────────────────────────────

@app.route("/api/results/<scan_id>")
def results(scan_id):
    if not _validate_scan_id(scan_id):
        return jsonify({"error": "Invalid scan_id format"}), 400
    try:
        findings = Finding.query.filter_by(scan_id=scan_id).all()
        return jsonify([_finding_dict(f) for f in findings])
    except Exception as e:
        logger.exception(f"[RESULTS] Failed: {e}")
        return jsonify({"error": "Failed to retrieve results"}), 500


# ── Modules ───────────────────────────────────────────────────────────────────

@app.route("/api/modules")
def get_modules():
    return jsonify([
        {"id": "subdomain-takeover",  "name": "Subdomain Takeover",       "icon": "Globe",        "path": "/scanner/subdomain-takeover"},
        {"id": "s3-buckets",          "name": "S3/Blob Bucket Checker",    "icon": "Database",     "path": "/scanner/s3-buckets"},
        {"id": "cors",                "name": "CORS Misconfiguration",     "icon": "Shield",       "path": "/scanner/cors"},
        {"id": "sensitive-files",     "name": "Sensitive File Exposure",   "icon": "FileWarning",  "path": "/scanner/sensitive-files"},
        {"id": "api-key-leak",        "name": "API Key Leak Detector",     "icon": "Key",          "path": "/scanner/api-key-leak"},
        {"id": "open-redirect",       "name": "Open Redirect Fuzzer",      "icon": "ExternalLink", "path": "/scanner/open-redirect"},
        {"id": "clickjacking",        "name": "Clickjacking Checker",      "icon": "Layers",       "path": "/scanner/clickjacking"},
        {"id": "dns-zone-transfer",   "name": "DNS Zone Transfer",         "icon": "Server",       "path": "/scanner/dns-zone-transfer"},
        {"id": "spf-dmarc",           "name": "SPF/DMARC Checker",         "icon": "Mail",         "path": "/scanner/spf-dmarc"},
        {"id": "rate-limit",          "name": "Rate Limit Tester",         "icon": "Gauge",        "path": "/scanner/rate-limit"},
        {"id": "nuclei",              "name": "Nuclei Vulnerability Scan", "icon": "Zap",          "path": "/scanner/nuclei"},
    ])


@app.route("/api/modules/<module_id>/config")
def get_module_config(module_id):
    configs = {
        "subdomain-takeover": [
            {"label": "Check CNAME records",         "type": "toggle",   "default": True},
            {"label": "Check A records",             "type": "toggle",   "default": True},
            {"label": "Verify takeover feasibility", "type": "checkbox", "default": True},
            {"label": "Include wildcard check",      "type": "checkbox", "default": False},
        ],
        "s3-buckets": [
            {"label": "Check public READ",  "type": "toggle",   "default": True},
            {"label": "Check public WRITE", "type": "toggle",   "default": True},
            {"label": "Enumerate objects",  "type": "checkbox", "default": False},
            {"label": "Check Azure Blob",   "type": "checkbox", "default": True},
        ],
        "cors": [
            {"label": "Test null origin",       "type": "toggle",   "default": True},
            {"label": "Test wildcard origin",   "type": "toggle",   "default": True},
            {"label": "Check credentials flag", "type": "checkbox", "default": True},
        ],
        "rate-limit": [
            {"label": "requests",        "type": "number",  "default": 30},
            {"label": "Follow redirects","type": "toggle",  "default": True},
        ],
        "nuclei": [
            {"label": "templates",    "type": "text",   "default": "", "placeholder": "Custom templates path (optional)"},
            {"label": "rate-limit",   "type": "number", "default": 10, "min": 1, "max": 100},
            {"label": "timeout",      "type": "number", "default": 30, "min": 5, "max": 300},
        ],
    }
    default = [
        {"label": "Deep scan mode",   "type": "toggle",   "default": False},
        {"label": "Follow redirects", "type": "toggle",   "default": True},
        {"label": "Verbose output",   "type": "checkbox", "default": True},
    ]
    return jsonify(configs.get(module_id, default))


# ── Guided Takeover Workflow ──────────────────────────────────────────────────

@app.route("/api/takeover/enumerate")
def takeover_enumerate_api():
    target = str(request.args.get("target") or "").strip()
    if not target:
        return jsonify({"error": "target required"}), 400
    return jsonify(takeover_enumerate(target))


@app.route("/api/takeover/triage", methods=["POST"])
def takeover_triage_api():
    data = request.get_json(silent=True) or {}
    subdomains = data.get("subdomains", [])
    if not isinstance(subdomains, list) or not subdomains:
        return jsonify({"error": "No subdomains provided"}), 400
    return jsonify(takeover_triage(subdomains))


@app.route("/api/takeover/scan", methods=["POST"])
def takeover_scan_api():
    data = request.get_json(silent=True) or {}
    cname_records = data.get("cname_records", [])
    if not isinstance(cname_records, list) or not cname_records:
        return jsonify({"error": "No CNAME records provided"}), 400
    return jsonify(takeover_scan_cnames(cname_records))


@app.route("/api/takeover/verify", methods=["POST"])
def takeover_verify_api():
    data = request.get_json(silent=True) or {}
    vulnerable = data.get("vulnerable", [])
    if not isinstance(vulnerable, list) or not vulnerable:
        return jsonify({"error": "No vulnerable records provided"}), 400
    return jsonify(takeover_verify(vulnerable))


# ── Findings ──────────────────────────────────────────────────────────────────

@app.route("/api/findings")
def get_findings():
    findings = Finding.query.order_by(Finding.timestamp.desc()).all()
    return jsonify([_finding_dict(f) for f in findings])


@app.route("/api/findings/recent")
def recent_findings():
    findings = Finding.query.order_by(Finding.timestamp.desc()).limit(20).all()
    return jsonify([_finding_dict(f) for f in findings])


@app.route("/api/findings/all")
def all_findings():
    severity = request.args.get("severity")
    module   = request.args.get("module")
    status   = request.args.get("status")
    q = Finding.query
    if severity: q = q.filter_by(severity=severity)
    if module:   q = q.filter_by(module=module)
    if status:   q = q.filter_by(status=status)
    return jsonify([_finding_dict(f) for f in q.order_by(Finding.timestamp.desc()).all()])


# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.route("/api/dashboard/stats")
def get_dashboard_stats():
    return jsonify({
        "totalScans":    Scan.query.count(),
        "totalFindings": Finding.query.count(),
        "critical":      Finding.query.filter_by(severity="critical").count(),
        "high":          Finding.query.filter_by(severity="high").count(),
        "medium":        Finding.query.filter_by(severity="medium").count(),
        "low":           Finding.query.filter_by(severity="low").count(),
    })


@app.route("/api/dashboard/activity")
def get_activity_feed():
    findings = Finding.query.order_by(Finding.timestamp.desc()).limit(20).all()
    return jsonify([
        {
            "time":    f.timestamp.isoformat() if f.timestamp else "",
            "type":    f.severity or "info",
            "message": f"[{(f.severity or 'info').upper()}] {f.finding} on {f.asset}",
        }
        for f in findings
    ])


# ── Scan History ──────────────────────────────────────────────────────────────

@app.route("/api/scans")
def get_scan_history():
    scans = Scan.query.order_by(Scan.started_at.desc()).all()
    return jsonify([s.to_dict() for s in scans])


@app.route("/api/scans/<scan_id>")
def get_scan_detail(scan_id):
    if not _validate_scan_id(scan_id):
        return jsonify({"error": "Invalid scan_id"}), 400
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify({**scan.to_dict(), "findings": [_finding_dict(f) for f in scan.findings]})


@app.route("/api/scans/clear", methods=["POST"])
def clear_scan_history():
    removed_findings = Finding.query.delete()
    removed_scans = Scan.query.delete()
    db.session.commit()
    return jsonify({"status": "ok", "removedScans": removed_scans, "removedFindings": removed_findings})


@app.route("/api/scans/delete", methods=["POST"])
def delete_selected_scans():
    data = request.get_json(silent=True) or {}
    scan_ids = data.get("scanIds", [])
    if not scan_ids or not isinstance(scan_ids, list):
        return jsonify({"error": "scanIds must be a non-empty array"}), 400
    # Validate all IDs
    invalid = [sid for sid in scan_ids if not _validate_scan_id(sid)]
    if invalid:
        return jsonify({"error": f"Invalid scan IDs: {invalid}"}), 400
    removed_findings = Finding.query.filter(Finding.scan_id.in_(scan_ids)).delete(synchronize_session=False)
    removed_scans = Scan.query.filter(Scan.id.in_(scan_ids)).delete(synchronize_session=False)
    db.session.commit()
    return jsonify({"status": "ok", "deleted": removed_scans, "findingsRemoved": removed_findings})


# ── Stats ─────────────────────────────────────────────────────────────────────

@app.route("/api/stats/severity")
def stats_severity():
    from sqlalchemy import func
    rows = db.session.query(Finding.severity, func.count()).group_by(Finding.severity).all()
    return jsonify({r[0]: r[1] for r in rows})


@app.route("/api/stats/modules")
def stats_modules():
    from sqlalchemy import func
    rows = db.session.query(Finding.module, func.count()).group_by(Finding.module).all()
    return jsonify({r[0]: r[1] for r in rows})


@app.route("/api/stats/overview")
def stats_overview():
    return jsonify({
        "total_scans":    Scan.query.count(),
        "total_findings": Finding.query.count(),
        "critical":       Finding.query.filter_by(severity="critical").count(),
        "high":           Finding.query.filter_by(severity="high").count(),
        "medium":         Finding.query.filter_by(severity="medium").count(),
        "low":            Finding.query.filter_by(severity="low").count(),
        "info":           Finding.query.filter_by(severity="info").count(),
    })


# ── Export ────────────────────────────────────────────────────────────────────

@app.route("/api/export/<scan_id>")
def export_scan(scan_id):
    if not _validate_scan_id(scan_id):
        return jsonify({"error": "Invalid scan_id"}), 400
    fmt = request.args.get("format", "json")
    findings = Finding.query.filter_by(scan_id=scan_id).all()
    data = [_finding_dict(f) for f in findings]
    if fmt == "csv":
        import csv, io
        si = io.StringIO()
        if data:
            w = csv.DictWriter(si, fieldnames=data[0].keys())
            w.writeheader()
            w.writerows(data)
        return Response(
            si.getvalue(), mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename={scan_id}.csv"},
        )
    return jsonify(data)


@app.route("/api/export/bulk", methods=["POST"])
def export_bulk():
    body = request.get_json(silent=True) or {}
    ids = body.get("ids", [])
    findings = (
        Finding.query.filter(Finding.id.in_(ids)).all()
        if ids else Finding.query.all()
    )
    return jsonify([_finding_dict(f) for f in findings])


# ── SPA Serving ───────────────────────────────────────────────────────────────

@app.route("/")
def serve_root():
    if app.static_folder and os.path.exists(os.path.join(app.static_folder, "index.html")):
        return send_from_directory(app.static_folder, "index.html")
    return jsonify({"status": "ok", "message": "BUGHUNTR API"})


@app.route("/<path:path>")
def serve_spa(path):
    if path.startswith("api/"):
        return jsonify({"error": "Not found"}), 404
    static_path = os.path.join(app.static_folder, path)
    if os.path.isfile(static_path):
        return send_from_directory(app.static_folder, path)
    if app.static_folder and os.path.exists(os.path.join(app.static_folder, "index.html")):
        return send_from_directory(app.static_folder, "index.html")
    return jsonify({"error": "Not found"}), 404


# ── Entry ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV") == "development"
    app.run(debug=debug, port=port, threaded=True, host="0.0.0.0")