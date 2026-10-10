"""Orchestrate scans using a common data model and persistence flow."""
from __future__ import annotations
import time
from collections import OrderedDict
from core.device_model import Device, DeviceStatus
from database.repository import Repository
from core.change_detector import detect_changes
from discovery.simulated import generate_simulated_devices
from discovery.local_network import DiscoveryDiagnostics, discover_local_network
from services.hostname_service import HostnameResolver


def deduplicate(devices: list[Device]) -> list[Device]:
    unique: OrderedDict[str, Device] = OrderedDict()
    for device in devices:
        key = device.stable_key
        if key in unique:
            prior = unique[key]
            if prior.ip_address != device.ip_address and prior.mac_address and device.mac_address and prior.ip_address != device.ip_address:
                continue
            for attr in ("hostname", "hostname_method", "mac_address", "manufacturer", "device_type"):
                prior_value = getattr(prior, attr)
                new_value = getattr(device, attr)
                if attr == "device_type":
                    if prior_value in (None, "Unknown") and new_value not in (None, "Unknown"):
                        setattr(prior, attr, new_value)
                elif prior_value is None and new_value is not None:
                    setattr(prior, attr, new_value)
            if prior.hostname_status in ("not_attempted", "not_found", "error") and device.hostname_status == "resolved":
                prior.hostname_status = device.hostname_status
            if prior.status == DeviceStatus.UNKNOWN and device.status != DeviceStatus.UNKNOWN:
                prior.status = device.status
            if device.first_seen < prior.first_seen:
                prior.first_seen = device.first_seen
            if device.last_seen > prior.last_seen:
                prior.last_seen = device.last_seen
        else:
            unique[key] = device
    return list(unique.values())


def run_scan(repo: Repository, *, mode: str = "simulation", seed: int = 20261010,
             count: int = 18, subnet: str | None = None, timeout: float = 1.5,
             authorized: bool = False, interface: str | None = None,
             missing_threshold: int = 2) -> tuple[str, list[Device], list[dict[str, str]]]:
    source = "simulation" if mode == "simulation" else "live_arp"
    diagnostics = DiscoveryDiagnostics(method="offline deterministic simulation" if mode == "simulation" else "Scapy Ethernet/ARP")
    repo.last_diagnostics = diagnostics
    scan = repo.start_scan(mode, source, subnet if mode == "live" else None, missing_threshold=missing_threshold)
    start = time.monotonic()
    try:
        if mode == "simulation": devices = generate_simulated_devices(seed=seed, count=count)
        elif mode == "live":
            if not subnet: raise ValueError("Enter an explicit private local IPv4 subnet.")
            devices = discover_local_network(
                subnet, timeout=timeout, authorized=authorized, diagnostics=diagnostics,
                interface=interface, hostname_resolver=HostnameResolver(),
            )
        else: raise ValueError("Mode must be 'simulation' or 'live'.")
        devices = deduplicate(devices)
        diagnostics.response_count = len(devices)
        diagnostics.normalized_device_count = len(devices)
        diagnostics.hostname_resolved_count = sum(bool(device.hostname) for device in devices)
        diagnostics.completed = True
        if mode == "simulation":
            diagnostics.message = f"Simulation completed; {len(devices)} device(s) generated."
            diagnostics.suggestion = "Simulation data is local and does not measure the connected network."
        repo.reconcile_identities(devices)
        repo.finish_scan(scan.scan_id, devices, duration=time.monotonic() - start)
        changes = detect_changes(repo, scan.scan_id, devices, missing_threshold)
        return scan.scan_id, devices, changes
    except Exception as exc:
        diagnostics.completed = False
        diagnostics.message = str(exc)
        diagnostics.suggestion = "Confirm the detected Wi-Fi subnet, authorization, and Scapy/Npcap permissions."
        repo.finish_scan(scan.scan_id, [], duration=time.monotonic() - start, status="failed", error=str(exc))
        raise
