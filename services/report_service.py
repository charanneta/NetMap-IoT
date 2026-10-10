"""CSV, JSON, and summary-report serialization from persisted snapshots."""
from __future__ import annotations
import csv, io, json
from datetime import datetime, timezone
from database.repository import Repository

FIELDS = ["device_id", "ip_address", "mac_address", "hostname", "hostname_method", "hostname_status", "device_type", "manufacturer", "status", "discovery_source", "first_seen", "observed_at"]

def _records(repo: Repository, scan_id: str) -> list[dict]:
    return [{field: (getattr(o, field).isoformat() if isinstance(getattr(o, field), datetime) else getattr(o, field)) for field in FIELDS} for o in repo.observations(scan_id)]

def export_csv(repo: Repository, scan_id: str) -> str:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=FIELDS); writer.writeheader(); writer.writerows(_records(repo, scan_id))
    return output.getvalue()

def export_json(repo: Repository, scan_id: str) -> str:
    scan = repo.session.get(__import__("database.repository", fromlist=["ScanSession"]).ScanSession, scan_id)
    if scan is None: raise KeyError(f"Unknown scan session {scan_id}")
    return json.dumps({"scan": {"scan_id": scan.scan_id, "mode": scan.mode, "source": scan.source,
        "scope": scan.scope, "status": scan.status, "started_at": scan.started_at.isoformat(),
        "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
        "duration_seconds": scan.duration_seconds, "device_count": scan.device_count}, "devices": _records(repo, scan_id)}, indent=2)

def summary_report(repo: Repository, scan_id: str) -> dict:
    payload = json.loads(export_json(repo, scan_id)); records = payload["devices"]
    payload["summary"] = {"device_count": len(records), "online": sum(r["status"] == "online" for r in records),
      "offline": sum(r["status"] == "offline" for r in records), "unknown": sum(r["status"] == "unknown" for r in records),
      "iot_count": sum("iot" in (r["device_type"] or "").lower() for r in records)}
    return payload
