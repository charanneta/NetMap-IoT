"""Device table filtering helpers."""
from core.device_model import Device

def filter_devices(devices: list[Device], *, query: str = "", device_type: str = "All", source: str = "All", status: str = "All") -> list[Device]:
    q = query.casefold().strip()
    result = []
    for d in devices:
        if q and q not in " ".join(str(v or "") for v in (d.ip_address,d.hostname,d.mac_address)).casefold(): continue
        if device_type != "All" and d.device_type != device_type: continue
        if source != "All" and d.discovery_source != source: continue
        if status != "All" and d.status.value != status: continue
        result.append(d)
    return result
