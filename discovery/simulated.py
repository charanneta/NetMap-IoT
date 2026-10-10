"""Offline deterministic virtual-network generator."""
from __future__ import annotations
import random
from datetime import datetime, timezone
from core.device_model import Device, DeviceStatus


def generate_simulated_devices(seed: int = 20261010, count: int = 18) -> list[Device]:
    """Generate repeatable synthetic devices; these are always labelled simulated."""
    rng = random.Random(seed)
    types = ["Router", "Laptop", "Desktop", "Smartphone", "Server", "Printer", "IoT Sensor", "Smart TV", "Camera"]
    manufacturers = ["Example Networks", "Northstar Devices", "Contoso", "Fabrikam", None]
    now = datetime.now(timezone.utc)
    devices = [Device(ip_address="192.168.10.1", mac_address="02:00:00:00:00:01", hostname="gateway.local",
                      device_type="Router", manufacturer="Example Networks", status=DeviceStatus.ONLINE,
                      discovery_source="simulation", first_seen=now, last_seen=now)]
    for idx in range(2, max(1, count) + 1):
        kind = types[(idx - 2) % len(types)]
        devices.append(Device(ip_address=f"192.168.10.{idx}",
                              mac_address=f"02:00:00:10:{(idx >> 8) & 255:02x}:{idx & 255:02x}",
                              hostname=f"{kind.lower().replace(' ', '-')}-{idx}.simulated",
                              device_type=kind, manufacturer=rng.choice(manufacturers),
                              status=DeviceStatus.ONLINE if rng.random() > .18 else DeviceStatus.UNKNOWN,
                              discovery_source="simulation", first_seen=now, last_seen=now))
    return devices
