from flask import Flask, jsonify, request, Response, stream_with_context, send_from_directory
from flask_cors import CORS
import uuid, json, time, threading, queue, os
from datetime import datetime
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
)
from db import db, Finding, Scan

app = Flask(__name__, static_folder='../dist', static_url_path='')
CORS(app)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///bbh.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)

# In-memory SSE queues per scan_id
scan_queues: dict[str, queue.Queue] = {}

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
}

with app.app_context():
    db.create_all()


# ── Scan trigger ──────────────────────────────────────────────────────────────

@app.route("/api/scan/<module>", methods=["POST"])
def trigger_scan(module):
    if module not in SCANNER_MAP:
        return jsonify({"error": "Unknown module"}), 404

    data = request.get_json()
    target = data.get("target", "").strip()
    options = data.get("options", {})

    if not target:
        return jsonify({"error": "Target required"}), 400

    scan_id = str(uuid.uuid4())
    scan_queues[scan_id] = queue.Queue()

    scan = Scan(id=scan_id, module=module, target=target, status="running",
                started_at=datetime.utcnow())
    with app.app_context():
        db.session.add(scan)
        db.session.commit()

    def run():
        q = scan_queues[scan_id]
        scanner = SCANNER_MAP[module]
        try:
            for event in scanner(target, options):
                # event = {"type": "log"|"finding"|"complete", ...}
                q.put(event)
                if event["type"] == "finding":
                    _save_finding(scan_id, module, event["data"])
        except Exception as e:
            q.put({"type": "log", "message": f"[ERROR] {e}"})
        finally:
            q.put({"type": "complete"})
            with app.app_context():
                s = Scan.query.get(scan_id)
                if s:
                    s.status = "complete"
                    s.finished_at = datetime.utcnow()
                    db.session.commit()

    threading.Thread(target=run, daemon=True).start()
    return jsonify({"scan_id": scan_id})


def _save_finding(scan_id, module, data):
    with app.app_context():
        f = Finding(
            id=str(uuid.uuid4()),
            scan_id=scan_id,
            module=module,
            asset=data.get("asset", ""),
            finding=data.get("finding", ""),
            severity=data.get("severity", "info"),
            status="new",
            evidence=json.dumps(data.get("evidence", {})),
            h1_report=data.get("h1_report", ""),
            timestamp=datetime.utcnow(),
        )
        db.session.add(f)
        db.session.commit()


# ── Frontend API bridge ───────────────────────────────────────────────────────

@app.route("/api/modules")
def get_modules():
    """Get list of available scanner modules."""
    modules = [
        {"id": "subdomain-takeover", "name": "Subdomain Takeover", "icon": "Globe", "path": "/scanner/subdomain-takeover"},
        {"id": "s3-bucket", "name": "S3/Blob Bucket Checker", "icon": "Database", "path": "/scanner/s3-bucket"},
        {"id": "cors-misconfig", "name": "CORS Misconfiguration", "icon": "Shield", "path": "/scanner/cors-misconfig"},
        {"id": "sensitive-files", "name": "Sensitive File Exposure", "icon": "FileWarning", "path": "/scanner/sensitive-files"},
        {"id": "api-key-leak", "name": "API Key Leak Detector", "icon": "Key", "path": "/scanner/api-key-leak"},
        {"id": "open-redirect", "name": "Open Redirect Fuzzer", "icon": "ExternalLink", "path": "/scanner/open-redirect"},
        {"id": "clickjacking", "name": "CORS + Clickjacking", "icon": "Layers", "path": "/scanner/clickjacking"},
        {"id": "dns-zone", "name": "DNS Zone Transfer", "icon": "Server", "path": "/scanner/dns-zone"},
        {"id": "spf-dmarc", "name": "SPF/DMARC Checker", "icon": "Mail", "path": "/scanner/spf-dmarc"},
        {"id": "rate-limit", "name": "Rate Limit Tester", "icon": "Gauge", "path": "/scanner/rate-limit"},
    ]
    return jsonify(modules)


@app.route("/api/findings")
def get_findings():
    """Get all findings."""
    findings = Finding.query.order_by(Finding.timestamp.desc()).all()
    return jsonify([_finding_dict(f) for f in findings])


@app.route("/api/dashboard/stats")
def get_dashboard_stats():
    """Get dashboard statistics."""
    total_scans = Scan.query.count()
    total_findings = Finding.query.count()
    stats = {
        "totalScans": total_scans,
        "totalFindings": total_findings,
        "critical": Finding.query.filter_by(severity="critical").count(),
        "high": Finding.query.filter_by(severity="high").count(),
        "medium": Finding.query.filter_by(severity="medium").count(),
        "low": Finding.query.filter_by(severity="low").count(),
    }
    return jsonify(stats)


@app.route("/api/dashboard/activity")
def get_activity_feed():
    """Get activity feed."""
    findings = Finding.query.order_by(Finding.timestamp.desc()).limit(20).all()
    activity = []
    severity_map = {
        "critical": "critical",
        "high": "high", 
        "medium": "medium",
        "low": "low",
        "info": "info"
    }
    for f in findings:
        activity.append({
            "time": f.timestamp.isoformat() if f.timestamp else "",
            "type": severity_map.get(f.severity, "info"),
            "message": f"Found {f.severity}: {f.finding} on {f.asset}",
        })
    return jsonify(activity)


@app.route("/api/modules/<module_id>/config")
def get_module_config(module_id):
    """Get configuration options for a specific module."""
    configs = {
        "subdomain-takeover": [
            {"label": "Check CNAME records", "type": "toggle", "default": True},
            {"label": "Check A records", "type": "toggle", "default": True},
            {"label": "Verify takeover feasibility", "type": "checkbox", "default": True},
            {"label": "Include wildcard check", "type": "checkbox", "default": False},
        ],
        "s3-bucket": [
            {"label": "Check public READ", "type": "toggle", "default": True},
            {"label": "Check public WRITE", "type": "toggle", "default": True},
            {"label": "Enumerate objects", "type": "checkbox", "default": False},
            {"label": "Check Azure Blob", "type": "checkbox", "default": True},
        ],
        "cors-misconfig": [
            {"label": "Test null origin", "type": "toggle", "default": True},
            {"label": "Test wildcard origin", "type": "toggle", "default": True},
            {"label": "Check credentials flag", "type": "checkbox", "default": True},
        ],
    }
    default_config = [
        {"label": "Deep scan mode", "type": "toggle", "default": False},
        {"label": "Follow redirects", "type": "toggle", "default": True},
        {"label": "Verbose output", "type": "checkbox", "default": True},
    ]
    return jsonify(configs.get(module_id, default_config))


@app.route("/api/scans/run", methods=["POST"])
def run_scan_api():
    """Frontend API endpoint to run a scan."""
    data = request.get_json()
    module_id = data.get("moduleId", "").strip()
    target = data.get("target", "").strip()
    
    if not module_id or not target:
        return jsonify({"error": "moduleId and target are required"}), 400
    
    # Map frontend module IDs to backend module names
    module_map = {
        "subdomain-takeover": "subdomain-takeover",
        "s3-bucket": "s3-buckets",
        "cors-misconfig": "cors",
        "sensitive-files": "sensitive-files",
        "api-key-leak": "api-key-leak",
        "open-redirect": "open-redirect",
        "clickjacking": "clickjacking",
        "dns-zone": "dns-zone-transfer",
        "spf-dmarc": "spf-dmarc",
        "rate-limit": "rate-limit",
    }
    
    backend_module = module_map.get(module_id, module_id)
    
    if backend_module not in SCANNER_MAP:
        return jsonify({"error": f"Unknown module: {module_id}"}), 404
    
    scan_id = str(uuid.uuid4())
    scan_queues[scan_id] = queue.Queue()
    
    scan = Scan(id=scan_id, module=module_id, target=target, status="running",
                started_at=datetime.utcnow())
    with app.app_context():
        db.session.add(scan)
        db.session.commit()
    
    def run():
        q = scan_queues[scan_id]
        scanner = SCANNER_MAP[backend_module]
        try:
            for event in scanner(target, data.get("options", {})):
                q.put(event)
                if event["type"] == "finding":
                    _save_finding(scan_id, module_id, event["data"])
        except Exception as e:
            q.put({"type": "log", "message": f"[ERROR] {e}"})
        finally:
            q.put({"type": "complete"})
            with app.app_context():
                s = Scan.query.get(scan_id)
                if s:
                    s.status = "complete"
                    s.finished_at = datetime.utcnow()
                    db.session.commit()
    
    threading.Thread(target=run, daemon=True).start()
    
    # Wait for scan to complete and return results
    results = []
    try:
        while True:
            event = scan_queues[scan_id].get(timeout=60)
            if event["type"] == "complete":
                break
    except:
        pass
    
    findings = Finding.query.filter_by(scan_id=scan_id).all()
    return jsonify([_finding_dict(f) for f in findings])


def stream(scan_id):
    if scan_id not in scan_queues:
        return jsonify({"error": "Scan not found"}), 404

    def generate():
        q = scan_queues[scan_id]
        while True:
            try:
                event = q.get(timeout=30)
                yield f"data: {json.dumps(event)}\n\n"
                if event["type"] == "complete":
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
    findings = Finding.query.filter_by(scan_id=scan_id).all()
    return jsonify([_finding_dict(f) for f in findings])


@app.route("/api/findings/recent")
def recent_findings():
    findings = Finding.query.order_by(Finding.timestamp.desc()).limit(20).all()
    return jsonify([_finding_dict(f) for f in findings])


@app.route("/api/findings/all")
def all_findings():
    severity = request.args.get("severity")
    module = request.args.get("module")
    status = request.args.get("status")

    q = Finding.query
    if severity:
        q = q.filter_by(severity=severity)
    if module:
        q = q.filter_by(module=module)
    if status:
        q = q.filter_by(status=status)

    findings = q.order_by(Finding.timestamp.desc()).all()
    return jsonify([_finding_dict(f) for f in findings])


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
    total_scans = Scan.query.count()
    total_findings = Finding.query.count()
    by_severity = {
        "critical": Finding.query.filter_by(severity="critical").count(),
        "high": Finding.query.filter_by(severity="high").count(),
        "medium": Finding.query.filter_by(severity="medium").count(),
        "low": Finding.query.filter_by(severity="low").count(),
        "info": Finding.query.filter_by(severity="info").count(),
    }
    return jsonify({"total_scans": total_scans, "total_findings": total_findings, **by_severity})


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
        return Response(si.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": f"attachment; filename={scan_id}.csv"})
    return jsonify(data)


@app.route("/api/export/bulk", methods=["POST"])
def export_bulk():
    body = request.get_json()
    ids = body.get("ids", [])
    findings = Finding.query.filter(Finding.id.in_(ids)).all() if ids else Finding.query.all()
    return jsonify([_finding_dict(f) for f in findings])


# ── Activity stream (global) ──────────────────────────────────────────────────

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

    return Response(stream_with_context(generate()), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache"})


# ── Helper ────────────────────────────────────────────────────────────────────

def _finding_dict(f: Finding) -> dict:
    return {
        "id": f.id,
        "scan_id": f.scan_id,
        "module": f.module,
        "asset": f.asset,
        "finding": f.finding,
        "severity": f.severity,
        "status": f.status,
        "evidence": json.loads(f.evidence) if f.evidence else {},
        "h1_report": f.h1_report,
        "timestamp": f.timestamp.isoformat() if f.timestamp else None,
    }


# ── SPA Routing (serve frontend for non-API routes) ──────────────────────────

@app.route('/')
def serve_root():
    """Serve the frontend index.html"""
    if os.path.exists(os.path.join(app.static_folder, 'index.html')):
        return send_from_directory(app.static_folder, 'index.html')
    return jsonify({"status": "ok", "message": "BUGHUNTR API Server"})


@app.route('/<path:path>')
def serve_spa(path):
    """Serve frontend files or index.html for SPA routing"""
    static_path = os.path.join(app.static_folder, path)
    
    # If it's a file that exists, serve it
    if os.path.isfile(static_path):
        return send_from_directory(app.static_folder, path)
    
    # Otherwise, serve index.html for SPA routing (unless it's an API route)
    if not path.startswith('api/'):
        if os.path.exists(os.path.join(app.static_folder, 'index.html')):
            return send_from_directory(app.static_folder, 'index.html')
    
    return jsonify({"error": "Not found"}), 404


if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    app.run(debug=debug, port=port, threaded=True, host='0.0.0.0')
