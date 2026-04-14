from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Scan(db.Model):
    __tablename__ = "scans"
    id = db.Column(db.String, primary_key=True)
    module = db.Column(db.String, nullable=False)
    target = db.Column(db.String, nullable=False)
    status = db.Column(db.String, default="running")
    started_at = db.Column(db.DateTime)
    finished_at = db.Column(db.DateTime)
    findings = db.relationship("Finding", backref="scan", lazy=True)

class Finding(db.Model):
    __tablename__ = "findings"
    id = db.Column(db.String, primary_key=True)
    scan_id = db.Column(db.String, db.ForeignKey("scans.id"), nullable=False)
    module = db.Column(db.String)
    asset = db.Column(db.String)
    finding = db.Column(db.String)
    severity = db.Column(db.String)
    status = db.Column(db.String, default="new")
    evidence = db.Column(db.Text)
    h1_report = db.Column(db.Text)
    timestamp = db.Column(db.DateTime)
