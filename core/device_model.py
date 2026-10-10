"""Shared normalized domain models for simulated and live observations."""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import uuid4


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class DeviceStatus(StrEnum):
    ONLINE = "online"
    OFFLINE = "offline"
    UNKNOWN = "unknown"


def _normalize_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = str(value).strip()
    return cleaned or None


@dataclass(slots=True)
class Device:
    ip_address: str
    mac_address: str | None = None
    hostname: str | None = None
    hostname_method: str | None = None
    hostname_status: str = "not_attempted"
    device_type: str = "Unknown"
    manufacturer: str | None = None
    status: DeviceStatus = DeviceStatus.UNKNOWN
    discovery_source: str = "unknown"
    first_seen: datetime = field(default_factory=utcnow)
    last_seen: datetime = field(default_factory=utcnow)
    scan_session_id: str | None = None
    device_id: str = field(default_factory=lambda: str(uuid4()))

    def __post_init__(self) -> None:
        import ipaddress
        self.ip_address = str(ipaddress.ip_address(self.ip_address))
        self.mac_address = _normalize_optional_text(self.mac_address)
        if self.mac_address:
            self.mac_address = self.mac_address.lower().replace("-", ":").replace(" ", "")
        self.hostname = _normalize_optional_text(self.hostname)
        self.hostname_method = _normalize_optional_text(self.hostname_method)
        self.hostname_status = (self.hostname_status or "not_attempted").strip()
        if self.hostname and self.hostname_method is None:
            self.hostname_method = "existing_metadata"
            self.hostname_status = "resolved"
        self.device_type = (self.device_type or "Unknown").strip() or "Unknown"
        self.manufacturer = _normalize_optional_text(self.manufacturer)
        self.status = DeviceStatus(self.status or "unknown")

    @property
    def stable_key(self) -> str:
        return f"mac:{self.mac_address}" if self.mac_address else f"ip:{self.ip_address}"

    def to_dict(self) -> dict[str, Any]:
        return {"device_id": self.device_id, "ip_address": self.ip_address,
                "mac_address": self.mac_address, "hostname": self.hostname,
                "hostname_method": self.hostname_method, "hostname_status": self.hostname_status,
                "device_type": self.device_type, "manufacturer": self.manufacturer,
                "status": self.status.value, "discovery_source": self.discovery_source,
                "first_seen": self.first_seen.isoformat(), "last_seen": self.last_seen.isoformat(),
                "scan_session_id": self.scan_session_id}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Device":
        values = dict(data)
        values["first_seen"] = datetime.fromisoformat(values["first_seen"]) if isinstance(values.get("first_seen"), str) else values.get("first_seen", utcnow())
        values["last_seen"] = datetime.fromisoformat(values["last_seen"]) if isinstance(values.get("last_seen"), str) else values.get("last_seen", utcnow())
        status = values.get("status")
        values["status"] = DeviceStatus(status) if status is not None else DeviceStatus.UNKNOWN
        return cls(**values)
