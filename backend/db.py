# from flask_sqlalchemy import SQLAlchemy
import json
import os
from datetime import datetime
import uuid

# db = SQLAlchemy()

# Mock database using JSON file storage
DB_FILE = "bbh_mock.db"

class MockDB:
    def __init__(self):
        self.data = {"scans": {}, "findings": {}}
        self.load()

    def load(self):
        if os.path.exists(DB_FILE):
            try:
                with open(DB_FILE, 'r') as f:
                    self.data = json.load(f)
            except:
                self.data = {"scans": {}, "findings": {}}

    def save(self):
        with open(DB_FILE, 'w') as f:
            json.dump(self.data, f, default=str)

db = MockDB()

class Scan:
    def __init__(self, id=None, module=None, target=None, status="running", started_at=None, finished_at=None):
        self.id = id or str(uuid.uuid4())
        self.module = module
        self.target = target
        self.status = status
        self.started_at = started_at or datetime.now()
        self.finished_at = finished_at
        self.findings = []

    def to_dict(self):
        total_findings = len(self.findings)
        critical_count = sum(1 for f in self.findings if f.severity == "critical")
        high_count = sum(1 for f in self.findings if f.severity == "high")

        return {
            "scanId": self.id,
            "module": self.module,
            "target": self.target,
            "status": self.status,
            "startTime": self.started_at.isoformat() if self.started_at else None,
            "endTime": self.finished_at.isoformat() if self.finished_at else None,
            "totalFindings": total_findings,
            "criticalCount": critical_count,
            "highCount": high_count,
        }

class Finding:
    def __init__(self, id=None, scan_id=None, module=None, asset=None, finding=None, severity=None, status="new", details="", evidence="", vulnerable_objects="[]", h1_report=None, timestamp=None):
        self.id = id or str(uuid.uuid4())
        self.scan_id = scan_id
        self.module = module
        self.asset = asset
        self.finding = finding
        self.severity = severity
        self.status = status
        self.details = details
        self.evidence = evidence
        self.vulnerable_objects = vulnerable_objects
        self.h1_report = h1_report
        self.timestamp = timestamp or datetime.now()

    def get_vulnerable_objects(self):
        """Parse JSON vulnerable objects"""
        try:
            return json.loads(self.vulnerable_objects) if self.vulnerable_objects else []
        except json.JSONDecodeError:
            return []

    def set_vulnerable_objects(self, objects):
        """Store vulnerable objects as JSON"""
        self.vulnerable_objects = json.dumps(objects)

    def to_dict(self):
        return {
            "id": self.id,
            "asset": self.asset,
            "finding": self.finding,
            "severity": self.severity,
            "status": self.status,
            "module": self.module,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "details": self.details,
            "vulnerableObjects": self.get_vulnerable_objects(),
        }

