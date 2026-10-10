"""Snapshot comparison; missing devices are offline only after repeated successful scans."""
from __future__ import annotations
from core.device_model import Device, DeviceStatus
from database.repository import Repository, ScanSession


def detect_changes(repo: Repository, scan_id: str, current: list[Device], missing_threshold: int = 2) -> list[dict[str, str]]:
    if missing_threshold < 1: raise ValueError("missing_threshold must be at least 1")
    current_scan = repo.session.get(ScanSession, scan_id)
    if current_scan is None: raise KeyError(f"Unknown scan session {scan_id}")
    sessions = [s for s in repo.scans(limit=1000) if s.status == "success" and s.scan_id != scan_id
                and s.mode == current_scan.mode and s.source == current_scan.source]
    sessions.sort(key=lambda s: s.started_at, reverse=True)
    prev_by_key = {}
    for session in sessions:
        for observation in repo.observations(session.scan_id):
            prev_by_key.setdefault(observation.stable_key, observation)
    latest_previous_keys = ({o.stable_key for o in repo.observations(sessions[0].scan_id)} if sessions else set())
    current_by_key = {d.stable_key: d for d in current}
    changes: list[dict[str, str]] = []
    for key, device in current_by_key.items():
        old = prev_by_key.get(key)
        if old is None:
            kind, detail = "new", f"First observed at {device.ip_address}"
        elif key not in latest_previous_keys:
            kind, detail = "reappeared", f"Observed again at {device.ip_address}"
        elif old.ip_address != device.ip_address:
            kind, detail = "changed_ip", f"IP changed from {old.ip_address} to {device.ip_address}"
        elif ((old.hostname and device.hostname and old.hostname != device.hostname)
              or (old.device_type not in (None, "Unknown") and device.device_type not in (None, "Unknown") and old.device_type != device.device_type)):
            kind, detail = "attribute_changed", f"Tracked attributes changed for {device.ip_address}"
        else:
            continue
        repo.add_change(scan_id, device.device_id, kind, detail)
        changes.append({"event_type": kind, "device_id": device.device_id, "details": detail})
    for key, old in prev_by_key.items():
        if key in current_by_key: continue
        misses = 1  # current scan is successful and the device is absent
        for session in sessions:
            snapshot = repo.observations(session.scan_id)
            if any(o.stable_key == key for o in snapshot): break
            misses += 1
        if misses >= missing_threshold:
            kind, detail = "missing", f"Not observed in {misses} consecutive successful scans; prior IP {old.ip_address}"
            repo.add_change(scan_id, old.device_id, kind, detail)
            changes.append({"event_type": kind, "device_id": old.device_id, "details": detail})
        else:
            detail = f"Not observed in {misses} consecutive successful scans; status remains unknown"
            repo.add_change(scan_id, old.device_id, "possibly_missing", detail)
            changes.append({"event_type": "possibly_missing", "device_id": old.device_id, "details": detail})
    return changes


def materialize_status_view(repo: Repository, scan_id: str, missing_threshold: int | None = None) -> list[Device]:
    """Return observed devices plus historical devices with conservative derived status.

    Derived offline devices are shown for dashboard context only; they are not added
    to the current scan snapshot or its exports.
    """
    scan = repo.session.get(ScanSession, scan_id)
    if scan is None: raise KeyError(f"Unknown scan session {scan_id}")
    missing_threshold = missing_threshold or scan.missing_threshold
    if missing_threshold < 1: raise ValueError("missing_threshold must be at least 1")
    sessions = [s for s in repo.scans(limit=1000) if s.status == "success" and s.mode == scan.mode and s.source == scan.source]
    sessions.sort(key=lambda s: s.started_at, reverse=True)
    current_obs = repo.observations(scan_id)
    present = {o.stable_key for o in current_obs}
    output = []
    for o in current_obs:
        output.append(Device(device_id=o.device_id, ip_address=o.ip_address, mac_address=o.mac_address,
            hostname=o.hostname, device_type=o.device_type or "Unknown", manufacturer=o.manufacturer,
            hostname_method=o.hostname_method, hostname_status=o.hostname_status or "not_attempted",
            status=o.status, discovery_source=o.discovery_source, first_seen=o.first_seen,
            last_seen=o.observed_at, scan_session_id=scan_id))
    historical: dict[str, list] = {}
    for session in sessions[1:]:
        for o in repo.observations(session.scan_id):
            if o.stable_key not in present: historical.setdefault(o.stable_key, []).append(o)
    for key, records in historical.items():
        misses = 1
        for session in sessions[1:]:
            if any(o.stable_key == key for o in repo.observations(session.scan_id)): break
            misses += 1
        newest = records[0]
        output.append(Device(device_id=newest.device_id, ip_address=newest.ip_address, mac_address=newest.mac_address,
            hostname=newest.hostname, device_type=newest.device_type or "Unknown", manufacturer=newest.manufacturer,
            hostname_method=newest.hostname_method, hostname_status=newest.hostname_status or "not_attempted",
            status=DeviceStatus.OFFLINE if misses >= missing_threshold else DeviceStatus.UNKNOWN,
            discovery_source=newest.discovery_source, first_seen=newest.first_seen,
            last_seen=newest.observed_at, scan_session_id=scan_id))
    return output
