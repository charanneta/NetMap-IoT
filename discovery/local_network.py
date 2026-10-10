"""Conservative authorized local-network discovery using Scapy ARP only."""
from __future__ import annotations
import ipaddress
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
from core.device_model import Device, DeviceStatus
from config.settings import MAX_LIVE_HOSTS
from services.hostname_service import HostnameResolver, HostnameResult


@dataclass(slots=True)
class DiscoveryDiagnostics:
    interface: str | None = None
    interface_name: str | None = None
    local_ip: str | None = None
    subnet: str | None = None
    gateway: str | None = None
    method: str = "Scapy Ethernet/ARP"
    permission_status: str = "Not checked"
    response_count: int = 0
    normalized_device_count: int = 0
    hostname_resolved_count: int = 0
    completed: bool = False
    message: str = ""
    suggestion: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "interface": self.interface,
            "interface_name": self.interface_name,
            "local_ip": self.local_ip,
            "subnet": self.subnet,
            "gateway": self.gateway,
            "method": self.method,
            "permission_status": self.permission_status,
            "response_count": self.response_count,
            "normalized_device_count": self.normalized_device_count,
            "hostname_resolved_count": self.hostname_resolved_count,
            "completed": self.completed,
            "message": self.message,
            "suggestion": self.suggestion,
        }


def network_identity(diagnostics: DiscoveryDiagnostics) -> tuple[str | None, str | None, str | None, str | None]:
    return (diagnostics.interface, diagnostics.local_ip, diagnostics.subnet, diagnostics.gateway)


def synchronize_subnet_state(
    current_value: str | None,
    previous_identity: tuple[str | None, str | None, str | None, str | None] | None,
    current_identity: tuple[str | None, str | None, str | None, str | None] | None,
    previous_detected_subnet: str | None,
    detected_subnet: str | None,
) -> tuple[str, tuple[str | None, str | None, str | None, str | None] | None, str | None]:
    """Synchronize an automatic subnet without overwriting same-network manual input."""
    value = (current_value or "").strip()
    if not detected_subnet or not current_identity:
        return "", None, None
    if previous_identity != current_identity:
        return detected_subnet, current_identity, detected_subnet
    if value == (previous_detected_subnet or ""):
        return detected_subnet, current_identity, detected_subnet
    return value, current_identity, previous_detected_subnet


def _interface_ipv4_addresses(conf, interface: str) -> list[str]:
    try:
        addresses = conf.iface_addresses(interface)
    except AttributeError:
        interface_info = getattr(conf, "ifaces", {}).get(interface)
        addresses = [getattr(interface_info, "ip", "")]
    except (IndexError, KeyError, OSError):
        return []
    return [address for address in addresses if isinstance(address, str) and _is_usable_ipv4(address)]


def _interface_diagnostics(conf, interface: str, interface_name: str | None = None) -> DiscoveryDiagnostics | None:
    addresses = _interface_ipv4_addresses(conf, interface)
    local_ip = next(
        (address for address in addresses if isinstance(address, str)
         and _is_usable_ipv4(address)),
        None,
    )
    if local_ip is None:
        return None
    local_address = ipaddress.ip_address(local_ip)
    default_prefix = 16 if local_address.is_link_local else 24
    diagnostics = DiscoveryDiagnostics(interface=interface, interface_name=interface_name or interface, local_ip=local_ip)
    diagnostics.subnet = str(ipaddress.ip_network(f"{local_ip}/{default_prefix}", strict=False))
    for route in getattr(conf.route, "routes", []):
        if len(route) < 5 or route[3] != interface or route[4] != local_ip:
            continue
        network, mask, gateway = route[0], route[1], route[2]
        if mask in (0, 0xFFFFFFFF):
            continue
        try:
            mask_value = str(ipaddress.IPv4Address(mask)) if isinstance(mask, int) else mask
            network_value = str(ipaddress.IPv4Address(network)) if isinstance(network, int) else network
            candidate = ipaddress.IPv4Network((network_value, mask_value))
            if local_address not in candidate:
                continue
            diagnostics.subnet = str(candidate)
            diagnostics.gateway = gateway if gateway != "0.0.0.0" else None
            break
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
            continue
    diagnostics.permission_status = "Scapy/Npcap available; packet permission not probed"
    return diagnostics


def _is_usable_ipv4(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return (
        isinstance(address, ipaddress.IPv4Address)
        and not address.is_loopback
        and (address.is_private or address.is_link_local)
    )


def detect_network_interfaces() -> list[DiscoveryDiagnostics]:
    """Return active interfaces with usable IPv4 configuration, without transmitting."""
    try:
        from scapy.all import conf
    except ImportError:
        return []
    interfaces: list[DiscoveryDiagnostics] = []
    for interface_id, interface in getattr(conf, "ifaces", {}).items():
        name = getattr(interface, "name", None) or str(interface)
        if "DISCONNECTED" in repr(interface).upper():
            continue
        diagnostics = _interface_diagnostics(conf, interface_id, name)
        if diagnostics is not None:
            interfaces.append(diagnostics)
    return interfaces


def validate_subnet(value: str) -> ipaddress.IPv4Network:
    try:
        network = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid subnet: {exc}") from exc
    if not isinstance(network, ipaddress.IPv4Network):
        raise ValueError("Live discovery currently supports IPv4 subnets only.")
    allowed = (ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"),
               ipaddress.ip_network("192.168.0.0/16"), ipaddress.ip_network("169.254.0.0/16"))
    if not any(network.subnet_of(block) for block in allowed):
        raise ValueError("Only RFC1918 private or IPv4 link-local networks are allowed; public ranges are rejected.")
    if network.num_addresses > MAX_LIVE_HOSTS:
        raise ValueError(f"Scope too large ({network.num_addresses} addresses). Use a subnet of at most {MAX_LIVE_HOSTS} addresses (typically /24 or narrower).")
    return network


def _route_context(network: ipaddress.IPv4Network, interface: str | None = None) -> tuple[str, str, str]:
    """Return the Scapy interface, local IPv4, and gateway for a target network."""
    try:
        from scapy.all import conf
    except ImportError as exc:
        raise RuntimeError("Scapy is not installed. Install project requirements.") from exc

    route = conf.route.route(str(network.network_address))
    selected_interface, local_ip, gateway = route[0], route[1], route[2]
    if interface is not None:
        selected_interface = interface
        addresses = _interface_ipv4_addresses(conf, interface)
        if not addresses:
            raise RuntimeError(f"Selected network interface is unavailable: {interface}")
        local_ip = addresses[0]
    try:
        local_address = ipaddress.ip_address(local_ip)
    except ValueError as exc:
        raise RuntimeError("Scapy could not determine an active local IPv4 address.") from exc
    if not isinstance(local_address, ipaddress.IPv4Address) or local_address.is_loopback or local_address.is_link_local:
        raise ValueError(f"Target subnet {network} is not attached to an active IPv4 interface (selected address: {local_ip}).")
    if local_address not in network:
        raise ValueError(
            f"Target subnet {network} does not match the active local network {local_address}/24. "
            "Enter the subnet shown by the network diagnostics."
        )
    return selected_interface, str(local_address), str(gateway) if gateway != "0.0.0.0" else ""


def detect_active_network(interface: str | None = None) -> DiscoveryDiagnostics:
    """Detect the active routed IPv4 network without transmitting packets."""
    diagnostics = DiscoveryDiagnostics()
    try:
        from scapy.all import conf
        interface, local_ip, gateway = _route_context(ipaddress.ip_network("0.0.0.0/0"), interface)
        detected_network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
        for route in conf.route.routes:
            if len(route) < 5:
                continue
            network, mask, _gateway, route_interface, route_ip = route[:5]
            if route_interface != interface or route_ip != local_ip or mask in (0, 0xFFFFFFFF):
                continue
            try:
                mask_value = str(ipaddress.IPv4Address(mask)) if isinstance(mask, int) else mask
                network_value = str(ipaddress.IPv4Address(network)) if isinstance(network, int) else network
                detected_network = ipaddress.IPv4Network((network_value, mask_value))
                break
            except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
                continue
        diagnostics.interface = interface
        interface_info = getattr(conf, "ifaces", {}).get(interface)
        diagnostics.interface_name = getattr(interface_info, "name", None) or interface
        diagnostics.local_ip = local_ip
        diagnostics.gateway = gateway or None
        diagnostics.subnet = str(detected_network)
        diagnostics.permission_status = "Scapy/Npcap available; packet permission not probed"
    except Exception as exc:
        diagnostics.message = str(exc)
        diagnostics.suggestion = "Check that Wi-Fi is connected and Scapy/Npcap is installed."
    return diagnostics


def discover_local_network(
    subnet: str,
    timeout: float = 1.5,
    *,
    authorized: bool = False,
    interface: str | None = None,
    diagnostics: DiscoveryDiagnostics | None = None,
    hostname_resolver: HostnameResolver | None = None,
) -> list[Device]:
    """ARP-probe one validated local subnet; no arbitrary/public scanning or fallback."""
    if not authorized:
        raise PermissionError("Explicit authorization is required before live discovery.")
    network = validate_subnet(subnet)
    if timeout <= 0 or timeout > 10:
        raise ValueError("Timeout must be greater than 0 and no more than 10 seconds.")
    try:
        from scapy.all import ARP, Ether, srp
    except ImportError as exc:
        raise RuntimeError("Scapy is not installed. Install project requirements; Windows also requires Npcap for live ARP discovery.") from exc
    selected_interface, local_ip, gateway = _route_context(network, interface)
    if diagnostics is not None:
        diagnostics.interface = selected_interface
        diagnostics.local_ip = local_ip
        diagnostics.subnet = str(network)
        diagnostics.gateway = gateway or None
        diagnostics.permission_status = "Scapy/Npcap available; packet permission not probed"
    try:
        answered, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network)),
            iface=selected_interface,
            timeout=timeout,
            verbose=False,
            retry=0,
        )
    except (PermissionError, OSError) as exc:
        raise RuntimeError(f"Live ARP discovery could not access the network interface: {exc}. Check interface selection and required permissions/Npcap.") from exc
    devices: list[Device] = []
    resolver = hostname_resolver or HostnameResolver()
    for _, response in answered:
        try:
            device = Device(ip_address=response.psrc, mac_address=response.hwsrc,
                                  status=DeviceStatus.ONLINE, device_type="Unknown",
                                  discovery_source="live_arp")
            devices.append(device)
        except ValueError:
            continue
    def identify(device: Device) -> Device:
        try:
            result = resolver.identify(device.ip_address, device.hostname)
        except Exception as exc:
            result = HostnameResult(None, "reverse_dns", "error", str(exc))
        device.hostname = result.hostname
        device.hostname_method = result.method
        device.hostname_status = result.status
        return device
    with ThreadPoolExecutor(max_workers=min(16, max(1, len(devices)))) as executor:
        devices = list(executor.map(identify, devices))
    if diagnostics is not None:
        diagnostics.response_count = len(answered)
        diagnostics.normalized_device_count = len(devices)
        diagnostics.hostname_resolved_count = sum(bool(device.hostname) for device in devices)
        diagnostics.completed = True
        diagnostics.permission_status = "Packet transmission succeeded"
        diagnostics.message = (
            "Scan completed; no devices responded to discovery."
            if not devices else f"Scan completed; {len(devices)} device(s) responded."
        )
        diagnostics.suggestion = (
            "Other clients may be isolated by the hotspot, or the target device may block/respond selectively."
            if not devices else "Review the observed devices and confirm the target subnet."
        )
    return devices
