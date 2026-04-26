from flask import Flask, jsonify, request, Response, stream_with_context, send_from_directory
# from flask_cors import CORS  # Temporarily disabled
import uuid, json, threading, queue, os, re, logging
from datetime import datetime, timedelta
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

app = Flask(__name__, static_folder='../dist', static_url_path='')
# CORS disabled for development
# CORS(app, origins=["http://localhost:8080", "http://localhost:8081", "http://localhost:8082", "http://127.0.0.1:8080", "http://127.0.0.1:8081", "http://127.0.0.1:8082"], supports_credentials=True)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///bbh.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# In-memory SSE queues per scan_id
scan_queues: dict[str, queue.Queue] = {}
scan_timestamps: dict[str, datetime] = {}  # Track when scans were created for cleanup

SCANNER_MAP = {
    "subdomain-takeover": scan_subdomain_takeover,
    "s3-buckets": scan_s3_buckets,
    "cors": scan_cors,
    "sensitive-files": scan_sensitive_files,
    "api-key-leak": scan_api_key_leak,
    "open-redirect": scan_open_redirect,
    "clickjacking": scan_clickjacking,
    "dns-zone-transfer": scan_dns_zone_transfer,
    "spf-dmarc": scan_spf_dmarc,
    "rate-limit": scan_rate_limit,
    "nuclei": scan_nuclei,
}

# Input validation rules
MAX_TARGET_LENGTH = 2048
MALICIOUS_PATTERNS = [
    r'<script[^>]*>.*?</script>',  # Script tags
    r'javascript:',  # JavaScript protocol
    r'onerror\s*=',  # Event handlers
    r'onclick\s*=',
    r'onload\s*=',
]

def validate_target(target: str) -> tuple[bool, str]:
    """Validate scan target for security and sanity."""
    if not target or not isinstance(target, str):
        return False, "Target must be a non-empty string"
    
    if len(target) > MAX_TARGET_LENGTH:
        return False, f"Target exceeds maximum length of {MAX_TARGET_LENGTH}"
    
    # Check for malicious patterns
    for pattern in MALICIOUS_PATTERNS:
        if re.search(pattern, target, re.IGNORECASE):
            return False, "Target contains suspicious characters or patterns"
    
    return True, ""

def cleanup_old_scans(max_age_seconds: int = 300):
    """Remove old completed scans from memory to prevent leaks."""
    now = datetime.utcnow()
    expired_scans = [
        scan_id for scan_id, created_at in scan_timestamps.items()
        if (now - created_at).total_seconds() > max_age_seconds
    ]
    for scan_id in expired_scans:
        scan_queues.pop(scan_id, None)
        scan_timestamps.pop(scan_id, None)

with app.app_context():
    db.create_all()
    # Lightweight schema repair for older SQLite files that predate new columns.
    inspector = inspect(db.engine)
    if inspector.has_table("findings"):
        existing = {col["name"] for col in inspector.get_columns("findings")}
        if "details" not in existing:
            db.session.execute(text("ALTER TABLE findings ADD COLUMN details TEXT DEFAULT ''"))
        if "vulnerable_objects" not in existing:
            db.session.execute(text("ALTER TABLE findings ADD COLUMN vulnerable_objects TEXT DEFAULT '[]'"))
        db.session.commit()


# ── Internal runner ───────────────────────────────────────────────────────────

def _run_scanner(scan_id: str, module_id: str, target: str, options: dict):
    """Run scanner in background thread, push events to queue."""
    q = scan_queues[scan_id]
    scanner = SCANNER_MAP[module_id]
    try:
        for event in scanner(target, options):
            # Validate event structure
            if not isinstance(event, dict):
                logger.error(f"[ERROR] Invalid event type: {type(event)}")
                continue
            
            event_type = event.get("type")
            if event_type not in ["log", "finding", "complete"]:
                logger.error(f"[ERROR] Unknown event type: {event_type}")
                continue
            
            # Filter out None/empty log messages
            if event_type == "log":
                msg = event.get("message")
                if not msg or not isinstance(msg, str):
                    continue
                q.put(event)
            elif event_type == "finding":
                # Validate finding data structure
                if not isinstance(event.get("data"), dict):
                    logger.error("[ERROR] Finding data is not a dict")
                    continue
                finding_data = event.get("data")
                if not _validate_finding_data(finding_data):
                    logger.error(f"[ERROR] Finding failed validation")
                    continue
                q.put(event)
                _save_finding(scan_id, module_id, finding_data)
            else:  # complete
                q.put(event)
    except Exception as e:
        logger.exception(f"[ERROR] Scanner {module_id} failed: {e}")
        q.put({"type": "log", "message": f"[ERROR] Scanner error: {str(e)}"})
    finally:
        q.put({"type": "complete"})
        # Schedule cleanup of this scan's queue after completion
        def cleanup_after_delay():
            import time
            time.sleep(10)  # Keep queue for 10 seconds for final result fetching
            scan_queues.pop(scan_id, None)
            scan_timestamps.pop(scan_id, None)
        
        threading.Thread(target=cleanup_after_delay, daemon=True).start()
        
        with app.app_context():
            try:
                s = db.session.get(Scan, scan_id)
                if s:
                    s.status = "complete"
                    s.finished_at = datetime.utcnow()
                    db.session.commit()
            except Exception as e:
                logger.exception(f"[ERROR] Failed to update scan status: {e}")


def _validate_finding_data(data: dict) -> bool:
    """Validate that finding data has all required fields."""
    try:
        # Required fields
        required = ["asset", "finding", "severity", "details", "h1_report"]
        for field in required:
            if not data.get(field) or not isinstance(data.get(field), str):
                return False
        
        # Validate severity
        severity = data.get("severity", "").lower()
        if severity not in ["critical", "high", "medium", "low", "info"]:
            return False
        
        # Validate evidence is JSON-serializable
        evidence = data.get("evidence", {})
        if isinstance(evidence, str):
            try:
                json.loads(evidence)
            except:
                return False
        
        # Validate vulnerable_objects is JSON-serializable
        vuln_objs = data.get("vulnerable_objects", "[]")
        if isinstance(vuln_objs, str):
            try:
                objs = json.loads(vuln_objs)
                if not isinstance(objs, list):
                    return False
            except:
                return False
        
        return True
    except Exception:
        return False


def _save_finding(scan_id, module, data):
    """Save a finding to the database with validation."""
    try:
        # Validate finding data
        if not _validate_finding_data(data):
            logger.error(f"[ERROR] Invalid finding data for module {module}")
            return
        
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
                evidence=json.dumps(data.get("evidence", {})) if isinstance(data.get("evidence"), str) else json.dumps(data.get("evidence", {})),
                h1_report=str(data.get("h1_report", "")).strip(),
                timestamp=datetime.utcnow(),
            )
            
            # Handle vulnerable_objects safely
            vuln_objs = data.get("vulnerable_objects", "[]")
            if isinstance(vuln_objs, str):
                f.vulnerable_objects = vuln_objs
            else:
                f.vulnerable_objects = json.dumps(vuln_objs)
            
            db.session.add(f)
            db.session.commit()
    except Exception as e:
        logger.exception(f"[ERROR] Failed to save finding: {e}")


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


# ── Scan trigger (SSE-based) ──────────────────────────────────────────────────

@app.route("/api/scan/<module>", methods=["POST"])
def trigger_scan(module):
    """Low-level scan trigger — returns scan_id immediately for SSE streaming."""
    if module not in SCANNER_MAP:
        return jsonify({"error": "Unknown module"}), 404

    data = request.get_json()
    if not isinstance(data, dict):
        data = {}
    target = (data.get("target") or "").strip()
    options = data.get("options", {})
    
    # Validate options is a dict
    if not isinstance(options, dict):
        options = {}

    if not target:
        return jsonify({"error": "Target required"}), 400

    # Validate target
    is_valid, error_msg = validate_target(target)
    if not is_valid:
        return jsonify({"error": f"Invalid target: {error_msg}"}), 400

    scan_id = str(uuid.uuid4())
    scan_queues[scan_id] = queue.Queue()
    scan_timestamps[scan_id] = datetime.utcnow()

    with app.app_context():
        scan = Scan(id=scan_id, module=module, target=target,
                    status="running", started_at=datetime.utcnow())
        db.session.add(scan)
        db.session.commit()

    threading.Thread(
        target=_run_scanner,
        args=(scan_id, module, target, options),
        daemon=True
    ).start()

    return jsonify({"scan_id": scan_id})


# ── Frontend unified scan endpoint ────────────────────────────────────────────

@app.route("/api/scans/run", methods=["POST"])
def run_scan_api():
    """
    Frontend-facing endpoint. Returns scan_id immediately.
    Frontend should then connect to GET /api/stream/<scan_id> for live events
    and GET /api/results/<scan_id> after completion.
    """
    # Cleanup old scans periodically
    cleanup_old_scans()
    
    data = request.get_json()
    if not isinstance(data, dict):
        data = {}
    module_id = (data.get("moduleId") or "").strip()
    target = (data.get("target") or "").strip()
    options = data.get("options", {})
    
    # Validate options is a dict
    if not isinstance(options, dict):
        options = {}

    if not module_id or not target:
        return jsonify({"error": "moduleId and target are required"}), 400

    if module_id not in SCANNER_MAP:
        return jsonify({"error": f"Unknown module: {module_id}. Valid: {list(SCANNER_MAP.keys())}"}), 404

    # Validate target
    is_valid, error_msg = validate_target(target)
    if not is_valid:
        return jsonify({"error": f"Invalid target: {error_msg}"}), 400

    scan_id = str(uuid.uuid4())
    scan_queues[scan_id] = queue.Queue()
    scan_timestamps[scan_id] = datetime.utcnow()

    with app.app_context():
        scan = Scan(id=scan_id, module=module_id, target=target,
                    status="running", started_at=datetime.utcnow())
        db.session.add(scan)
        db.session.commit()

    threading.Thread(
        target=_run_scanner,
        args=(scan_id, module_id, target, options),
        daemon=True
    ).start()

    return jsonify({"scan_id": scan_id, "status": "running"})


@app.route("/api/import/burp", methods=["POST"])
def import_burp_json():
    """
    Import Burp Suite JSON export and convert to findings.
    Expects multipart/form-data with 'file' field containing Burp JSON.
    """
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    
    try:
        data = json.load(file)
    except json.JSONDecodeError as e:
        return jsonify({"error": f"Invalid JSON file: {str(e)}"}), 400
    except Exception as e:
        return jsonify({"error": f"Error reading file: {str(e)}"}), 400
    
    if not isinstance(data, list):
        return jsonify({"error": "Expected JSON array of issues"}), 400
    
    # Create a synthetic scan for bulk imports
    import_scan_id = str(uuid.uuid4())
    with app.app_context():
        scan = Scan(
            id=import_scan_id,
            module="burp-import",
            target="[bulk-import]",
            status="complete",
            started_at=datetime.utcnow(),
            finished_at=datetime.utcnow()
        )
        db.session.add(scan)
        db.session.commit()
    
    imported_count = 0
    for issue in data:
        finding = _parse_burp_issue(issue)
        if finding:
            _save_finding(import_scan_id, "burp-import", finding)
            imported_count += 1
    
    return jsonify({"message": f"Imported {imported_count} findings from Burp JSON", "scan_id": import_scan_id}), 200


# ── SSE stream ────────────────────────────────────────────────────────────────

@app.route("/api/stream/<scan_id>")
def stream(scan_id):
    """SSE endpoint — streams log/finding/complete events for a scan."""
    if scan_id not in scan_queues:
        # Scan might already be done — return complete immediately
        return Response(
            "data: {\"type\": \"complete\"}\n\n",
            mimetype="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    def generate():
        q = scan_queues[scan_id]
        while True:
            try:
                event = q.get(timeout=30)
                yield f"data: {json.dumps(event)}\n\n"
                if event["type"] == "complete":
                    scan_queues.pop(scan_id, None)
                    break
            except queue.Empty:
                yield "data: {\"type\": \"ping\"}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Results ───────────────────────────────────────────────────────────────────

@app.route("/api/results/<scan_id>")
def results(scan_id):
    """Get results for a scan with access validation."""
    if not scan_id or not isinstance(scan_id, str):
        return jsonify({"error": "Invalid scan_id"}), 400
    
    # Validate scan_id format (should be UUID)
    try:
        import uuid
        uuid.UUID(scan_id)
    except ValueError:
        return jsonify({"error": "Invalid scan_id format"}), 400
    
    try:
        findings = Finding.query.filter_by(scan_id=scan_id).all()
        return jsonify([_finding_dict(f) for f in findings])
    except Exception as e:
        logger.exception(f"[ERROR] Failed to retrieve results: {e}")
        return jsonify({"error": "Failed to retrieve results"}), 500


# ── Modules ───────────────────────────────────────────────────────────────────

@app.route("/api/modules")
def get_modules():
    modules = [
        {"id": "subdomain-takeover",  "name": "Subdomain Takeover",      "icon": "Globe",        "path": "/scanner/subdomain-takeover"},
        {"id": "s3-buckets",          "name": "S3/Blob Bucket Checker",   "icon": "Database",     "path": "/scanner/s3-buckets"},
        {"id": "cors",                "name": "CORS Misconfiguration",    "icon": "Shield",       "path": "/scanner/cors"},
        {"id": "sensitive-files",     "name": "Sensitive File Exposure",  "icon": "FileWarning",  "path": "/scanner/sensitive-files"},
        {"id": "api-key-leak",        "name": "API Key Leak Detector",    "icon": "Key",          "path": "/scanner/api-key-leak"},
        {"id": "open-redirect",       "name": "Open Redirect Fuzzer",     "icon": "ExternalLink", "path": "/scanner/open-redirect"},
        {"id": "clickjacking",        "name": "CORS + Clickjacking",      "icon": "Layers",       "path": "/scanner/clickjacking"},
        {"id": "dns-zone-transfer",   "name": "DNS Zone Transfer",        "icon": "Server",       "path": "/scanner/dns-zone-transfer"},
        {"id": "spf-dmarc",           "name": "SPF/DMARC Checker",        "icon": "Mail",         "path": "/scanner/spf-dmarc"},
        {"id": "rate-limit",          "name": "Rate Limit Tester",        "icon": "Gauge",        "path": "/scanner/rate-limit"},
        {"id": "nuclei",              "name": "Nuclei Vulnerability Scan", "icon": "Zap",         "path": "/scanner/nuclei"},
    ]
    return jsonify(modules)


@app.route("/api/modules/<module_id>/config")
def get_module_config(module_id):
    configs = {
        "subdomain-takeover": [
            {"label": "Check CNAME records",        "type": "toggle",   "default": True},
            {"label": "Check A records",            "type": "toggle",   "default": True},
            {"label": "Verify takeover feasibility","type": "checkbox", "default": True},
            {"label": "Include wildcard check",     "type": "checkbox", "default": False},
        ],
        "s3-buckets": [
            {"label": "Check public READ",   "type": "toggle",   "default": True},
            {"label": "Check public WRITE",  "type": "toggle",   "default": True},
            {"label": "Enumerate objects",   "type": "checkbox", "default": False},
            {"label": "Check Azure Blob",    "type": "checkbox", "default": True},
        ],
        "cors": [
            {"label": "Test null origin",       "type": "toggle",   "default": True},
            {"label": "Test wildcard origin",   "type": "toggle",   "default": True},
            {"label": "Check credentials flag", "type": "checkbox", "default": True},
        ],
        "rate-limit": [
            {"label": "Request count", "type": "number", "default": 30},
            {"label": "Follow redirects", "type": "toggle", "default": True},
        ],
        "nuclei": [
            {"label": "templates", "type": "text", "default": "", "placeholder": "Path to custom templates (optional)"},
            {"label": "rate-limit", "type": "number", "default": 10, "min": 1, "max": 100},
            {"label": "timeout", "type": "number", "default": 30, "min": 5, "max": 300},
        ],
    }
    default_config = [
        {"label": "Deep scan mode",    "type": "toggle",   "default": False},
        {"label": "Follow redirects",  "type": "toggle",   "default": True},
        {"label": "Verbose output",    "type": "checkbox", "default": True},
    ]
    return jsonify(configs.get(module_id, default_config))


# ── Guided takeover workflow ──────────────────────────────────────────────────

@app.route("/api/takeover/enumerate")
def takeover_enumerate_api():
    target = (request.args.get("target") or "").strip()
    if not target:
        return jsonify({"error": "Target required"}), 400
    return jsonify(takeover_enumerate(target))


@app.route("/api/takeover/triage", methods=["POST"])
def takeover_triage_api():
    data = request.get_json() or {}
    subdomains = data.get("subdomains", [])
    if not isinstance(subdomains, list) or not subdomains:
        return jsonify({"error": "No subdomains provided"}), 400
    return jsonify(takeover_triage(subdomains))


@app.route("/api/takeover/scan", methods=["POST"])
def takeover_scan_api():
    data = request.get_json() or {}
    cname_records = data.get("cname_records", [])
    if not isinstance(cname_records, list) or not cname_records:
        return jsonify({"error": "No CNAME records provided"}), 400
    return jsonify(takeover_scan_cnames(cname_records))


@app.route("/api/takeover/verify", methods=["POST"])
def takeover_verify_api():
    data = request.get_json() or {}
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

    findings = q.order_by(Finding.timestamp.desc()).all()
    return jsonify([_finding_dict(f) for f in findings])


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
            "message": f"[{f.severity.upper()}] {f.finding} on {f.asset}",
        }
        for f in findings
    ])


# ── Scans history ─────────────────────────────────────────────────────────────

@app.route("/api/scans")
def get_scan_history():
    scans = Scan.query.order_by(Scan.started_at.desc()).all()
    return jsonify([s.to_dict() for s in scans])


@app.route("/api/scans/<scan_id>")
def get_scan_detail(scan_id):
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify({**scan.to_dict(), "findings": [_finding_dict(f) for f in scan.findings]})


@app.route("/api/scans/clear", methods=["POST"])
def clear_scan_history():
    removed_findings = Finding.query.delete()
    removed_scans = Scan.query.delete()
    db.session.commit()
    return jsonify({
        "status": "ok",
        "removedScans": removed_scans,
        "removedFindings": removed_findings,
    })


@app.route("/api/scans/delete", methods=["POST"])
def delete_selected_scans():
    """Delete specific scans by ID."""
    data = request.get_json() or {}
    scan_ids = data.get("scanIds", [])
    
    if not scan_ids or not isinstance(scan_ids, list):
        return jsonify({"error": "scanIds must be a non-empty array"}), 400
    
    # Delete findings for these scans
    removed_findings = Finding.query.filter(Finding.scan_id.in_(scan_ids)).delete()
    # Delete the scans
    removed_scans = Scan.query.filter(Scan.id.in_(scan_ids)).delete()
    db.session.commit()
    
    return jsonify({
        "status": "ok",
        "deleted": removed_scans,
        "findingsRemoved": removed_findings,
    })


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
            headers={"Content-Disposition": f"attachment; filename={scan_id}.csv"}
        )
    return jsonify(data)


@app.route("/api/export/bulk", methods=["POST"])
def export_bulk():
    body = request.get_json()
    ids = body.get("ids", [])
    findings = Finding.query.filter(Finding.id.in_(ids)).all() if ids else Finding.query.all()
    return jsonify([_finding_dict(f) for f in findings])


# ── Global activity SSE ───────────────────────────────────────────────────────

activity_queue: queue.Queue = queue.Queue()

@app.route("/api/stream/activity")
def activity_stream():
    def generate():
        while True:
            try:
                event = activity_queue.get(timeout=30)
                yield f"data: {json.dumps(event)}\n\n"
            except queue.Empty:
                yield "data: {\"type\": \"ping\"}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache"},
    )


# ── Frontend SPA serving ──────────────────────────────────────────────────────

@app.route('/')
def serve_root():
    if app.static_folder and os.path.exists(os.path.join(app.static_folder, 'index.html')):
        return send_from_directory(app.static_folder, 'index.html')
    return jsonify({"status": "ok", "message": "BUGHUNTR API Server"})


@app.route('/<path:path>')
def serve_spa(path):
    if path.startswith('api/'):
        return jsonify({"error": "Not found"}), 404
    static_path = os.path.join(app.static_folder, path)
    if os.path.isfile(static_path):
        return send_from_directory(app.static_folder, path)
    if app.static_folder and os.path.exists(os.path.join(app.static_folder, 'index.html')):
        return send_from_directory(app.static_folder, 'index.html')
    return jsonify({"error": "Not found"}), 404


# ── Entry ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    app.run(debug=debug, port=port, threaded=True, host='0.0.0.0')