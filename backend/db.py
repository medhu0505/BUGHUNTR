"""
db.py — SQLAlchemy models for BUGHUNTR.
Replaces the mock JSON-file storage with a proper ORM layer
that app.py already expects (SQLAlchemy session, Finding, Scan).
"""

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json
import uuid

db = SQLAlchemy()


class Scan(db.Model):
    __tablename__ = "scans"

    id          = db.Column(db.String(36),  primary_key=True, default=lambda: str(uuid.uuid4()))
    module      = db.Column(db.String(64),  nullable=False)
    target      = db.Column(db.String(2048),nullable=False)
    status      = db.Column(db.String(16),  nullable=False, default="running")
    started_at  = db.Column(db.DateTime,    nullable=False, default=datetime.utcnow)
    finished_at = db.Column(db.DateTime,    nullable=True)

    # Relationship — lazy="dynamic" lets you filter without loading all rows
    findings = db.relationship(
        "Finding",
        backref="scan",
        lazy="select",
        cascade="all, delete-orphan",
    )

    def to_dict(self) -> dict:
        finding_list = self.findings if isinstance(self.findings, list) else self.findings.all() if hasattr(self.findings, 'all') else []
        total   = len(finding_list)
        critical = sum(1 for f in finding_list if f.severity == "critical")
        high     = sum(1 for f in finding_list if f.severity == "high")
        return {
            "scanId":        self.id,
            "module":        self.module,
            "target":        self.target,
            "status":        self.status,
            "startTime":     self.started_at.isoformat()  if self.started_at  else None,
            "endTime":       self.finished_at.isoformat() if self.finished_at else None,
            "totalFindings": total,
            "criticalCount": critical,
            "highCount":     high,
        }


class Finding(db.Model):
    __tablename__ = "findings"

    id                = db.Column(db.String(36),   primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id           = db.Column(db.String(36),   db.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    module            = db.Column(db.String(64),   nullable=False)
    asset             = db.Column(db.String(2048), nullable=False)
    finding           = db.Column(db.Text,         nullable=False)
    severity          = db.Column(db.String(16),   nullable=False, default="info", index=True)
    status            = db.Column(db.String(16),   nullable=False, default="new")
    details           = db.Column(db.Text,         nullable=False, default="")
    evidence          = db.Column(db.Text,         nullable=False, default="{}")
    vulnerable_objects= db.Column(db.Text,         nullable=False, default="[]")
    h1_report         = db.Column(db.Text,         nullable=False, default="")
    timestamp         = db.Column(db.DateTime,     nullable=False, default=datetime.utcnow, index=True)

    def get_vulnerable_objects(self) -> list:
        try:
            result = json.loads(self.vulnerable_objects or "[]")
            return result if isinstance(result, list) else []
        except (json.JSONDecodeError, TypeError):
            return []

    def set_vulnerable_objects(self, objects: list):
        self.vulnerable_objects = json.dumps(objects if isinstance(objects, list) else [])

    def get_evidence(self) -> dict:
        try:
            result = json.loads(self.evidence or "{}")
            return result if isinstance(result, dict) else {}
        except (json.JSONDecodeError, TypeError):
            return {}

    def to_dict(self) -> dict:
        return {
            "id":               self.id,
            "scan_id":          self.scan_id,
            "module":           self.module,
            "asset":            self.asset,
            "finding":          self.finding,
            "severity":         self.severity,
            "status":           self.status,
            "details":          self.details or "",
            "evidence":         self.get_evidence(),
            "vulnerableObjects":self.get_vulnerable_objects(),
            "h1_report":        self.h1_report or "",
            "timestamp":        self.timestamp.isoformat() if self.timestamp else None,
        }