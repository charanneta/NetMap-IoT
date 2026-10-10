"""Bounded, evidence-based hostname identification for discovered devices."""
from __future__ import annotations

import socket
import threading
import time
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True, slots=True)
class HostnameResult:
    hostname: str | None
    method: str | None
    status: str
    detail: str = ""


class HostnameResolver:
    """Resolve hostnames without allowing name lookup to block a scan indefinitely."""

    def __init__(
        self,
        *,
        timeout: float = 0.35,
        ttl: float = 300.0,
        negative_ttl: float = 30.0,
        reverse_lookup: Callable[[str], tuple[str, list[str], list[str]]] | None = None,
    ) -> None:
        if timeout <= 0 or ttl <= 0 or negative_ttl <= 0:
            raise ValueError("Hostname resolver timeouts and cache TTLs must be positive.")
        self.timeout = timeout
        self.ttl = ttl
        self.negative_ttl = negative_ttl
        self._reverse_lookup = reverse_lookup or socket.gethostbyaddr
        self._cache: dict[str, tuple[float, HostnameResult]] = {}
        self._lock = threading.Lock()

    def resolve(self, ip_address: str, existing_hostname: str | None = None) -> HostnameResult:
        if existing_hostname:
            return HostnameResult(existing_hostname, "existing_metadata", "resolved")
        now = time.monotonic()
        with self._lock:
            cached = self._cache.get(ip_address)
            if cached and cached[0] > now:
                return cached[1]
        previous_timeout = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(self.timeout)
            hostname = self._reverse_lookup(ip_address)[0].strip().rstrip(".")
            if not hostname or hostname == ip_address:
                result = HostnameResult(None, "reverse_dns", "not_found", "No PTR hostname was returned.")
            else:
                result = HostnameResult(hostname, "reverse_dns", "resolved")
        except (socket.herror, socket.gaierror, socket.timeout, TimeoutError, OSError) as exc:
            result = HostnameResult(None, "reverse_dns", "not_found", str(exc))
        finally:
            socket.setdefaulttimeout(previous_timeout)
        with self._lock:
            self._cache[ip_address] = (now + (self.ttl if result.hostname else self.negative_ttl), result)
        return result

    def identify(self, ip_address: str, existing_hostname: str | None = None) -> HostnameResult:
        """Run supported identification methods in priority order.

        NetBIOS and mDNS are intentionally optional: no third-party package is
        required, and unavailable methods must never make ARP discovery fail.
        """
        return self.resolve(ip_address, existing_hostname)
