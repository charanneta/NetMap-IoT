"""Persistence repository for scan metadata, observed snapshots, and changes."""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Iterable
from uuid import uuid4
from sqlalchemy import String, DateTime, Integer, Text, ForeignKey, select, desc
from sqlalchemy.orm import Mapped, mapped_column, relationship, Session
from core.device_model import Device, DeviceStatus
from database.db import Base

class ScanSession(Base):
    __tablename__ = "scan_sessions"
    scan_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    mode: Mapped[str] = mapped_column(String(24), nullable=False)
    source: Mapped[str] = mapped_column(String(40), nullable=False)
    scope: Mapped[str | None] = mapped_column(String(80))
    status: Mapped[str] = mapped_column(String(20), default="running", nullable=False)
    duration_seconds: Mapped[float | None] = mapped_column()
    device_count: Mapped[int] = mapped_column(Integer, default=0)
    missing_threshold: Mapped[int] = mapped_column(Integer, default=2, nullable=False)
    error: Mapped[str | None] = mapped_column(Text)
    observations: Mapped[list["Observation"]] = relationship(back_populates="scan", cascade="all, delete-orphan")

class Observation(Base):
    __tablename__ = "observations"
    observation_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    scan_id: Mapped[str] = mapped_column(ForeignKey("scan_sessions.scan_id", ondelete="CASCADE"), index=True)
    device_id: Mapped[str] = mapped_column(String(36), index=True)
    stable_key: Mapped[str] = mapped_column(String(80), index=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    mac_address: Mapped[str | None] = mapped_column(String(32))
    hostname: Mapped[str | None] = mapped_column(String(255))
    hostname_method: Mapped[str | None] = mapped_column(String(40))
    hostname_status: Mapped[str] = mapped_column(String(24), default="not_attempted")
    device_type: Mapped[str] = mapped_column(String(80), default="Unknown")
    manufacturer: Mapped[str | None] = mapped_column(String(120))
    status: Mapped[str] = mapped_column(String(16), default="online")
    discovery_source: Mapped[str] = mapped_column(String(40))
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    scan: Mapped[ScanSession] = relationship(back_populates="observations")

class ChangeEvent(Base):
    __tablename__ = "change_events"
    event_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    scan_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    device_id: Mapped[str] = mapped_column(String(36), nullable=False)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    details: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

class Repository:
    def __init__(self, session: Session):
        self.session = session
        self.last_diagnostics = None

    def start_scan(self, mode: str, source: str, scope: str | None = None, missing_threshold: int = 2) -> ScanSession:
        started_at = datetime.now(timezone.utc)
        previous = self.session.scalar(select(ScanSession).order_by(desc(ScanSession.started_at)).limit(1))
        previous_started_at = previous.started_at if previous is not None else None
        if previous_started_at is not None and previous_started_at.tzinfo is None:
            previous_started_at = previous_started_at.replace(tzinfo=timezone.utc)
        if previous_started_at is not None and started_at <= previous_started_at:
            from datetime import timedelta
            started_at = previous_started_at + timedelta(microseconds=1)
        scan = ScanSession(scan_id=str(uuid4()), started_at=started_at, mode=mode, source=source, scope=scope, status="running", missing_threshold=missing_threshold)
        self.session.add(scan); self.session.commit(); return scan

    def finish_scan(self, scan_id: str, devices: Iterable[Device], *, duration: float, status: str = "success", error: str | None = None) -> ScanSession:
        scan = self.session.get(ScanSession, scan_id)
        if scan is None: raise KeyError(f"Unknown scan session {scan_id}")
        items = list(devices)
        for device in items:
            device.scan_session_id = scan_id
            self.session.add(Observation(scan_id=scan_id, device_id=device.device_id, stable_key=device.stable_key,
                ip_address=device.ip_address, mac_address=device.mac_address, hostname=device.hostname,
                hostname_method=device.hostname_method, hostname_status=device.hostname_status,
                device_type=device.device_type, manufacturer=device.manufacturer, status=device.status.value,
                discovery_source=device.discovery_source, first_seen=device.first_seen, observed_at=device.last_seen))
        scan.finished_at = datetime.now(timezone.utc); scan.duration_seconds = max(0.0, duration)
        scan.device_count = len(items); scan.status = status; scan.error = error
        self.session.commit(); return scan

    def reconcile_identities(self, devices: Iterable[Device]) -> None:
        """Reuse stable internal IDs and first-seen timestamps within each data source."""
        for device in devices:
            criteria = (Observation.stable_key == device.stable_key,
                        Observation.discovery_source == device.discovery_source)
            newest = self.session.scalar(select(Observation).where(*criteria).order_by(desc(Observation.observed_at)).limit(1))
            if newest is None: continue
            earliest = self.session.scalar(select(Observation).where(*criteria).order_by(Observation.observed_at).limit(1))
            device.device_id = newest.device_id
            device.first_seen = earliest.first_seen if earliest else newest.first_seen

    def latest_scan(self) -> ScanSession | None:
        return self.session.scalar(select(ScanSession).where(ScanSession.status == "success").order_by(desc(ScanSession.started_at)).limit(1))

    def scans(self, limit: int = 100) -> list[ScanSession]:
        return list(self.session.scalars(select(ScanSession).order_by(desc(ScanSession.started_at)).limit(limit)))

    def observations(self, scan_id: str) -> list[Observation]:
        return list(self.session.scalars(select(Observation).where(Observation.scan_id == scan_id).order_by(Observation.ip_address)))

    def changes(self, scan_id: str | None = None, limit: int = 500) -> list[ChangeEvent]:
        q = select(ChangeEvent)
        if scan_id: q = q.where(ChangeEvent.scan_id == scan_id)
        return list(self.session.scalars(q.order_by(desc(ChangeEvent.created_at)).limit(limit)))

    def add_change(self, scan_id: str, device_id: str, event_type: str, details: str = "") -> None:
        self.session.add(ChangeEvent(scan_id=scan_id, device_id=device_id, event_type=event_type, details=details, created_at=datetime.now(timezone.utc)))
        self.session.commit()
