from __future__ import annotations
import csv, io, json
from types import SimpleNamespace
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from core.device_model import Device, DeviceStatus
from database.db import Base
from database.repository import Repository, ScanSession
from discovery.simulated import generate_simulated_devices
from discovery.local_network import (
    detect_active_network,
    detect_network_interfaces,
    discover_local_network,
    network_identity,
    synchronize_subnet_state,
    validate_subnet,
)
from services.scan_service import deduplicate, run_scan
from services.report_service import export_csv, export_json, summary_report
from services.hostname_service import HostnameResolver
from core.change_detector import detect_changes

@pytest.fixture
def repo():
    engine=create_engine("sqlite:///:memory:",connect_args={"check_same_thread":False})
    Base.metadata.create_all(engine)
    session=sessionmaker(bind=engine,expire_on_commit=False)()
    yield Repository(session)
    session.close(); engine.dispose()

def test_simulation_is_deterministic():
    a=generate_simulated_devices(seed=91,count=14); b=generate_simulated_devices(seed=91,count=14)
    assert [(x.ip_address,x.mac_address,x.hostname,x.device_type,x.manufacturer) for x in a] == [(x.ip_address,x.mac_address,x.hostname,x.device_type,x.manufacturer) for x in b]
    assert all(d.discovery_source=="simulation" for d in a)

def test_device_schema_validates_ip_and_unknowns():
    d=Device(ip_address="192.168.1.5",status="unknown",device_type="")
    assert d.device_type=="Unknown" and d.mac_address is None and d.manufacturer is None
    assert d.status is DeviceStatus.UNKNOWN
    with pytest.raises(ValueError): Device(ip_address="not-an-ip")

def test_deduplicate_and_conflicting_mac():
    a=Device(ip_address="192.168.1.4",mac_address="02:00:00:00:00:01",hostname=None)
    b=Device(ip_address="192.168.1.4",mac_address="02:00:00:00:00:01",hostname="host")
    c=Device(ip_address="192.168.1.5",mac_address="02:00:00:00:00:01")
    result=deduplicate([a,b,c])
    assert len(result)==1 and result[0].hostname=="host"


def test_missing_optional_fields_normalize_to_unknowns():
    d=Device(ip_address="192.168.1.5",status=None,hostname="",manufacturer="",mac_address="",device_type="")
    assert d.status is DeviceStatus.UNKNOWN
    assert d.hostname is None
    assert d.manufacturer is None
    assert d.mac_address is None
    assert d.device_type == "Unknown"
    restored=Device.from_dict({"ip_address":"192.168.1.10","status":None})
    assert restored.status is DeviceStatus.UNKNOWN


def test_deduplicate_merges_more_specific_identity_fields():
    a=Device(ip_address="192.168.1.8",mac_address="02:00:00:00:00:08",hostname=None,device_type="Unknown",status=DeviceStatus.UNKNOWN)
    b=Device(ip_address="192.168.1.8",mac_address="02:00:00:00:00:08",hostname="workstation01",device_type="Laptop",manufacturer="Example",status=DeviceStatus.ONLINE)
    result=deduplicate([a,b])
    assert len(result)==1
    assert result[0].hostname == "workstation01"
    assert result[0].device_type == "Laptop"
    assert result[0].status is DeviceStatus.ONLINE
    assert result[0].manufacturer == "Example"


def test_persistence_and_export(repo):
    scan=repo.start_scan("simulation","simulation")
    ds=generate_simulated_devices(count=5)
    repo.finish_scan(scan.scan_id,ds,duration=.05)
    assert len(repo.observations(scan.scan_id))==5
    rows=list(csv.DictReader(io.StringIO(export_csv(repo,scan.scan_id))))
    payload=json.loads(export_json(repo,scan.scan_id))
    assert len(rows)==5 and len(payload["devices"])==5
    assert summary_report(repo,scan.scan_id)["summary"]["device_count"]==5

def test_empty_export_is_well_formed(repo):
    scan=repo.start_scan("live","live_arp","192.168.1.0/24")
    repo.finish_scan(scan.scan_id,[],duration=0)
    assert len(list(csv.DictReader(io.StringIO(export_csv(repo,scan.scan_id)))))==0
    assert json.loads(export_json(repo,scan.scan_id))["devices"]==[]

def test_change_detector_new_then_missing_threshold(repo):
    old=Device(ip_address="192.168.1.4",mac_address="02:00:00:00:00:04",discovery_source="simulation")
    s1=repo.start_scan("simulation","simulation"); repo.finish_scan(s1.scan_id,[old],duration=.1)
    s2=repo.start_scan("simulation","simulation"); repo.finish_scan(s2.scan_id,[],duration=.1)
    assert any(c["event_type"]=="possibly_missing" for c in detect_changes(repo,s2.scan_id,[],missing_threshold=2))
    s3=repo.start_scan("simulation","simulation"); repo.finish_scan(s3.scan_id,[],duration=.1)
    assert any(c["event_type"]=="missing" for c in detect_changes(repo,s3.scan_id,[],missing_threshold=2))

def test_validate_private_and_reject_public_and_large():
    assert str(validate_subnet("192.168.4.9/24"))=="192.168.4.0/24"
    with pytest.raises(ValueError): validate_subnet("8.8.8.0/24")
    with pytest.raises(ValueError): validate_subnet("10.0.0.0/16")
    with pytest.raises(ValueError): validate_subnet("2001:db8::/64")
    with pytest.raises(ValueError): validate_subnet("bad")

def test_live_requires_explicit_authorization():
    with pytest.raises(PermissionError): discover_local_network("192.168.1.0/24",authorized=False)

def test_run_scan_records_failure_and_rejects_invalid_mode(repo):
    with pytest.raises(ValueError): run_scan(repo,mode="typo")
    failures=repo.scans()
    assert len(failures)==1 and failures[0].status=="failed"

def test_simulated_scan_is_persisted(repo):
    scan_id,ds,_=run_scan(repo,mode="simulation",seed=2,count=7)
    assert len(ds)==7 and len(repo.observations(scan_id))==7


def test_reappearing_device_is_distinguished(repo):
    from core.change_detector import detect_changes
    device=Device(ip_address="192.168.1.6",mac_address="02:00:00:00:00:06",discovery_source="simulation")
    s1=repo.start_scan("simulation","simulation"); repo.finish_scan(s1.scan_id,[device],duration=.1)
    s2=repo.start_scan("simulation","simulation"); repo.finish_scan(s2.scan_id,[],duration=.1); detect_changes(repo,s2.scan_id,[],2)
    returning=Device(ip_address="192.168.1.6",mac_address="02:00:00:00:00:06",discovery_source="simulation")
    s3=repo.start_scan("simulation","simulation"); repo.finish_scan(s3.scan_id,[returning],duration=.1)
    events=detect_changes(repo,s3.scan_id,[returning],2)
    assert any(e["event_type"]=="reappeared" for e in events)

def test_derived_offline_status_waits_for_threshold_and_is_not_exported(repo):
    from core.change_detector import materialize_status_view
    device=Device(ip_address="192.168.1.7",mac_address="02:00:00:00:00:07",discovery_source="simulation")
    s1=repo.start_scan("simulation","simulation"); repo.finish_scan(s1.scan_id,[device],duration=.1)
    s2=repo.start_scan("simulation","simulation"); repo.finish_scan(s2.scan_id,[],duration=.1)
    first=materialize_status_view(repo,s2.scan_id,2)
    assert len(first)==1 and first[0].status is DeviceStatus.UNKNOWN
    s3=repo.start_scan("simulation","simulation"); repo.finish_scan(s3.scan_id,[],duration=.1)
    second=materialize_status_view(repo,s3.scan_id,2)
    assert len(second)==1 and second[0].status is DeviceStatus.OFFLINE
    assert repo.observations(s3.scan_id)==[]


def test_current_scan_observations_exclude_prior_devices(repo):
    laptop = Device(ip_address="192.168.1.2", mac_address="02:00:00:00:00:02", discovery_source="live_arp")
    friend = Device(ip_address="192.168.1.3", mac_address="02:00:00:00:00:03", discovery_source="live_arp")
    first = repo.start_scan("live", "live_arp", "192.168.1.0/24", missing_threshold=2)
    repo.finish_scan(first.scan_id, [laptop, friend], duration=.1)
    second = repo.start_scan("live", "live_arp", "192.168.1.0/24", missing_threshold=2)
    repo.finish_scan(second.scan_id, [laptop], duration=.1)

    current = repo.observations(second.scan_id)
    historical = repo.observations(first.scan_id)
    assert len(current) == 1
    assert current[0].stable_key == laptop.stable_key
    assert len(historical) == 2
    assert friend.stable_key not in {observation.stable_key for observation in current}

    changes = detect_changes(repo, second.scan_id, [laptop], missing_threshold=2)
    assert any(change["event_type"] == "possibly_missing" for change in changes)


def test_failed_scan_does_not_create_current_offline_observation(repo):
    device = Device(ip_address="192.168.1.4", mac_address="02:00:00:00:00:04", discovery_source="live_arp")
    first = repo.start_scan("live", "live_arp", "192.168.1.0/24", missing_threshold=1)
    repo.finish_scan(first.scan_id, [device], duration=.1)
    failed = repo.start_scan("live", "live_arp", "192.168.1.0/24", missing_threshold=1)
    repo.finish_scan(failed.scan_id, [], duration=.1, status="failed", error="permission denied")

    assert repo.observations(failed.scan_id) == []
    assert repo.latest_scan().scan_id == first.scan_id
    assert not any(event.scan_id == failed.scan_id for event in repo.changes())


def test_device_identity_and_first_seen_are_stable_across_scans(repo):
    from services.scan_service import run_scan
    scan1, devices1, _=run_scan(repo,mode="simulation",seed=77,count=6)
    records1={o.stable_key:(o.device_id,o.first_seen) for o in repo.observations(scan1)}
    scan2, devices2, _=run_scan(repo,mode="simulation",seed=77,count=6)
    records2={o.stable_key:(o.device_id,o.first_seen) for o in repo.observations(scan2)}
    assert records1.keys()==records2.keys()
    assert all(records1[key]==records2[key] for key in records1)


def test_live_timeout_bounds_are_enforced_before_probe():
    with pytest.raises(ValueError,match="Timeout"):
        discover_local_network("192.168.1.0/24",timeout=11,authorized=True)


def test_hostname_reverse_dns_resolution_and_cache():
    calls = []

    def reverse_lookup(ip):
        calls.append(ip)
        return ("laptop.local.", [], [ip])

    resolver = HostnameResolver(reverse_lookup=reverse_lookup)
    first = resolver.identify("192.168.1.9")
    second = resolver.identify("192.168.1.9")
    assert first.hostname == "laptop.local"
    assert first.method == "reverse_dns"
    assert first.status == "resolved"
    assert second == first
    assert calls == ["192.168.1.9"]


def test_hostname_missing_ptr_is_cached_as_not_found():
    calls = []

    def reverse_lookup(ip):
        calls.append(ip)
        raise OSError("no PTR")

    resolver = HostnameResolver(reverse_lookup=reverse_lookup)
    result = resolver.identify("192.168.1.10")
    assert result.hostname is None
    assert result.status == "not_found"
    resolver.identify("192.168.1.10")
    assert calls == ["192.168.1.10"]


def test_existing_hostname_metadata_wins_without_lookup():
    def fail_lookup(ip):
        raise AssertionError("existing metadata must not trigger lookup")

    result = HostnameResolver(reverse_lookup=fail_lookup).identify("192.168.1.11", "known-device")
    assert result.hostname == "known-device"
    assert result.method == "existing_metadata"
    assert result.status == "resolved"


def test_active_network_detection_uses_mocked_route(monkeypatch):
    import scapy.all as scapy_all

    fake_conf = SimpleNamespace(
        route=SimpleNamespace(
            route=lambda target: ("wifi0", "10.0.0.25", "10.0.0.1"),
            routes=[
                (0, 0, "10.0.0.1", "wifi0", "10.0.0.25", 10),
                (int.from_bytes(b"\x0a\x00\x00\x00", "big"), int.from_bytes(b"\xff\xff\xff\x00", "big"), "0.0.0.0", "wifi0", "10.0.0.25", 10),
            ],
        ),
        iface_addresses=lambda interface: ["10.0.0.25"],
    )
    monkeypatch.setattr(scapy_all, "conf", fake_conf)
    diagnostics = detect_active_network()
    assert diagnostics.interface == "wifi0"
    assert diagnostics.local_ip == "10.0.0.25"
    assert diagnostics.subnet == "10.0.0.0/24"


def test_network_switch_refreshes_detected_subnet():
    old = ("wifi0", "10.0.0.25", "10.0.0.0/24", "10.0.0.1")
    new = ("wifi1", "192.168.50.25", "192.168.50.0/24", "192.168.50.1")
    value, identity, detected = synchronize_subnet_state(
        "10.0.0.0/24", old, new, "10.0.0.0/24", "192.168.50.0/24"
    )
    assert (value, identity, detected) == ("192.168.50.0/24", new, "192.168.50.0/24")


def test_valid_manual_subnet_is_preserved_on_same_network():
    identity = ("wifi0", "10.0.0.25", "10.0.0.0/24", "10.0.0.1")
    value, _, _ = synchronize_subnet_state(
        "10.0.0.0/25", identity, identity, "10.0.0.0/24", "10.0.0.0/24"
    )
    assert value == "10.0.0.0/25"


def test_detection_failure_does_not_supply_hardcoded_subnet():
    value, identity, detected = synchronize_subnet_state(
        "", ("wifi0", "10.0.0.25", "10.0.0.0/24", "10.0.0.1"), None,
        "10.0.0.0/24", None
    )
    assert value == "" and identity is None and detected is None


def test_interface_inventory_returns_only_usable_ipv4(monkeypatch):
    import scapy.all as scapy_all

    class DisconnectedInterface:
        name = "Ethernet"
        ip = "169.254.1.10"

        def __repr__(self):
            return "<NetworkInterface_Win Ethernet [DISCONNECTED]>"

    fake_conf = SimpleNamespace(
        ifaces={
            "wifi0": SimpleNamespace(name="Wi-Fi"),
            "loopback": SimpleNamespace(name="lo"),
            "virtual": SimpleNamespace(name="virtual0"),
            "ethernet": DisconnectedInterface(),
        },
        iface_addresses=lambda interface: {
            "wifi0": ["10.0.0.25"],
            "lo": ["127.0.0.1"],
            "virtual0": [],
            "ethernet": ["169.254.1.10"],
        }[interface],
        route=SimpleNamespace(routes=[
            (int.from_bytes(b"\x0a\x00\x00\x00", "big"), int.from_bytes(b"\xff\xff\xff\x00", "big"),
             "10.0.0.1", "wifi0", "10.0.0.25", 10),
        ]),
    )
    monkeypatch.setattr(scapy_all, "conf", fake_conf)
    interfaces = detect_network_interfaces()
    assert [item.interface for item in interfaces] == ["wifi0"]
    assert interfaces[0].interface_name == "Wi-Fi"
    assert interfaces[0].subnet == "10.0.0.0/24"


def test_live_discovery_selects_route_interface_and_normalizes_response(monkeypatch):
    import scapy.all as scapy_all

    fake_conf = SimpleNamespace(
        route=SimpleNamespace(route=lambda target: ("wifi0", "10.0.0.25", "10.0.0.1")),
        iface_addresses=lambda interface: ["10.0.0.25"],
    )
    observed = {}

    def fake_srp(packet, **kwargs):
        observed.update(kwargs)
        response = SimpleNamespace(psrc="10.0.0.30", hwsrc="AA-BB-CC-DD-EE-FF")
        return [(object(), response)], []

    monkeypatch.setattr(scapy_all, "conf", fake_conf)
    monkeypatch.setattr(scapy_all, "srp", fake_srp)
    devices = discover_local_network("10.0.0.0/24", authorized=True)
    assert observed["iface"] == "wifi0"
    assert len(devices) == 1
    assert devices[0].ip_address == "10.0.0.30"
    assert devices[0].mac_address == "aa:bb:cc:dd:ee:ff"


def test_hostname_failure_does_not_discard_valid_device(monkeypatch):
    import scapy.all as scapy_all

    fake_conf = SimpleNamespace(
        route=SimpleNamespace(route=lambda target: ("wifi0", "10.0.0.25", "10.0.0.1")),
        iface_addresses=lambda interface: ["10.0.0.25"],
    )
    monkeypatch.setattr(scapy_all, "conf", fake_conf)
    monkeypatch.setattr(scapy_all, "srp", lambda *args, **kwargs: [
        [(object(), SimpleNamespace(psrc="10.0.0.30", hwsrc="aa:bb:cc:dd:ee:30"))], []
    ])

    class BrokenResolver:
        def identify(self, ip_address, existing_hostname=None):
            raise RuntimeError("resolver unavailable")

    diagnostics = SimpleNamespace(
        response_count=0,
        normalized_device_count=0,
        hostname_resolved_count=0,
        interface=None,
        local_ip=None,
        subnet=None,
        gateway=None,
        permission_status="",
    )
    devices = discover_local_network(
        "10.0.0.0/24", authorized=True, hostname_resolver=BrokenResolver(), diagnostics=diagnostics
    )
    assert len(devices) == 1
    assert devices[0].hostname is None
    assert devices[0].hostname_status == "error"
    assert diagnostics.response_count == 1
    assert diagnostics.normalized_device_count == 1


def test_wrong_private_subnet_is_rejected_before_probe(monkeypatch):
    import scapy.all as scapy_all

    called = False
    fake_conf = SimpleNamespace(
        route=SimpleNamespace(route=lambda target: ("wifi0", "10.0.0.25", "10.0.0.1")),
        iface_addresses=lambda interface: ["10.0.0.25"],
    )

    def fail_if_called(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("ARP probe must not run for a non-local target subnet")

    monkeypatch.setattr(scapy_all, "conf", fake_conf)
    monkeypatch.setattr(scapy_all, "srp", fail_if_called)
    with pytest.raises(ValueError, match="does not match the active local network"):
        discover_local_network("192.168.1.0/24", authorized=True)
    assert called is False


def test_scan_history_survives_database_reopen(tmp_path):
    db_path=tmp_path/"history.sqlite3"
    engine=create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)
    factory=sessionmaker(bind=engine,expire_on_commit=False)
    first=factory(); first_repo=Repository(first)
    scan=first_repo.start_scan("simulation","simulation")
    first_repo.finish_scan(scan.scan_id,generate_simulated_devices(count=5),duration=.2)
    scan_id=scan.scan_id
    first.close(); engine.dispose()
    reopened=create_engine(f"sqlite:///{db_path}")
    second=None
    try:
        reopened_factory=sessionmaker(bind=reopened,expire_on_commit=False)
        second=reopened_factory(); second_repo=Repository(second)
        assert second_repo.latest_scan().scan_id==scan_id
        assert len(second_repo.observations(scan_id))==5
    finally:
        if second is not None: second.close()
        reopened.dispose()


def test_live_topology_without_router_marks_anchor_unverified():
    from ui.topology import build_topology
    device=Device(ip_address="192.168.1.10",discovery_source="live_arp")
    figure=build_topology([device],mode="live")
    assert any("gateway unknown" in str(trace.name).lower() for trace in figure.data)
    assert any(str(text).startswith("Anchor") for text in figure.data[-1].text)
