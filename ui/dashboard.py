"""Dashboard metrics and presentation helpers."""
from collections import Counter
from core.device_model import Device

def dashboard_metrics(devices: list[Device]) -> dict[str, int]:
    return {"total": len(devices), "online": sum(d.status.value == "online" for d in devices),
            "offline": sum(d.status.value == "offline" for d in devices),
            "unknown": sum(d.status.value == "unknown" for d in devices),
            "iot": sum("iot" in d.device_type.lower() for d in devices)}

def type_counts(devices: list[Device]) -> dict[str, int]:
    return dict(Counter(d.device_type for d in devices))
