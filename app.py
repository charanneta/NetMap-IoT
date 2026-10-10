from __future__ import annotations
import json
import pandas as pd
import plotly.express as px
import streamlit as st
from sqlalchemy import select
from config.settings import APP_NAME, DEFAULT_SIMULATION_SEED, DEFAULT_SCAN_TIMEOUT, DEFAULT_MISSING_THRESHOLD
from core.device_model import Device
from database.db import SessionLocal, init_db
from database.repository import Repository, ScanSession, Observation
from services.scan_service import run_scan
from discovery.local_network import (
    detect_active_network,
    detect_network_interfaces,
    network_identity,
    synchronize_subnet_state,
)
from services.report_service import export_csv, export_json, summary_report
from ui.dashboard import dashboard_metrics, type_counts
from ui.devices import filter_devices
from ui.topology import build_topology

st.set_page_config(page_title=APP_NAME, page_icon="🗺️", layout="wide")
st.markdown("""<style>
.block-container{padding-top:1.4rem;max-width:1500px}.hero{padding:1.2rem 1.4rem;border:1px solid #21364b;border-radius:14px;background:linear-gradient(120deg,#101f30,#122d3b)}
.hero h1{margin:0;color:#f2f7fb}.hero p{color:#afc1d2;margin:.4rem 0 0}.stMetric{background:#111f2d;padding:14px;border:1px solid #24394d;border-radius:12px}
.small-note{color:#94a9bd;font-size:.9rem}
</style>""", unsafe_allow_html=True)
init_db()

@st.cache_resource
def get_db(): return SessionLocal()
db = get_db(); repo = Repository(db)

st.sidebar.title("NetMap IoT")
page = st.sidebar.radio("Navigation", ["Overview", "Devices", "Topology", "History & Changes", "Reports"], label_visibility="collapsed")
st.sidebar.markdown("---")
st.sidebar.caption("Network discovery for authorized local environments")

sessions = repo.scans(limit=100)
latest = repo.latest_scan()
current_observations = repo.observations(latest.scan_id) if latest else []
def to_device(o):
    from datetime import datetime, timezone
    return Device(device_id=o.device_id, ip_address=o.ip_address, mac_address=o.mac_address, hostname=o.hostname,
                  device_type=o.device_type or "Unknown", manufacturer=o.manufacturer,
                  hostname_method=o.hostname_method, hostname_status=o.hostname_status or "not_attempted",
                  status=o.status, discovery_source=o.discovery_source,
                  first_seen=o.first_seen, last_seen=o.observed_at, scan_session_id=o.scan_id)
devices = [to_device(o) for o in current_observations]

st.markdown('<div class="hero"><h1>NetMap IoT</h1><p>Device discovery, scan history, and an honest view of observed network relationships.</p></div>', unsafe_allow_html=True)
st.write("")

with st.sidebar.expander("Run a scan", expanded=True):
    mode = st.radio("Discovery mode", ["Simulation", "Live network"], help="Simulation is offline and deterministic. Live mode is limited to an explicitly authorized private IPv4 subnet.")
    seed = st.number_input("Simulation seed", min_value=0, value=DEFAULT_SIMULATION_SEED, step=1, disabled=mode != "Simulation")
    count = st.slider("Simulated devices (including gateway)", 5, 60, 18, disabled=mode != "Simulation")
    interfaces = detect_network_interfaces() if mode == "Live network" else []
    interface_names = [item.interface for item in interfaces if item.interface]
    if len(interface_names) > 1:
        selected_interface = st.selectbox(
            "Network interface",
            interface_names,
            format_func=lambda value: next(
                (item.interface_name or value for item in interfaces if item.interface == value),
                value,
            ),
            key="live_interface",
        )
    else:
        selected_interface = interface_names[0] if interface_names else None
    active_network = (
        next((item for item in interfaces if item.interface == selected_interface), None)
        if selected_interface else None
    )
    if mode == "Live network" and selected_interface:
        detected_selected = detect_active_network(selected_interface)
        if detected_selected.local_ip:
            detected_selected.interface_name = (
                active_network.interface_name if active_network else detected_selected.interface_name
            )
            active_network = detected_selected
    current_identity = network_identity(active_network) if active_network else None
    subnet_value, previous_identity, detected_subnet = synchronize_subnet_state(
        st.session_state.get("live_subnet", ""),
        st.session_state.get("live_network_identity"),
        current_identity,
        st.session_state.get("live_detected_subnet"),
        active_network.subnet if active_network else None,
    )
    st.session_state["live_subnet"] = subnet_value
    st.session_state["live_network_identity"] = previous_identity
    st.session_state["live_detected_subnet"] = detected_subnet
    subnet = st.text_input("Private subnet (CIDR)", key="live_subnet", disabled=mode != "Live network")
    timeout = st.slider("Probe timeout (seconds)", .2, 5.0, DEFAULT_SCAN_TIMEOUT, .1, disabled=mode != "Live network")
    threshold = st.number_input("Missing threshold (successful scans)", 1, 10, DEFAULT_MISSING_THRESHOLD)
    authorized = st.checkbox("I am authorized to discover devices on this subnet", disabled=mode != "Live network")
    run = st.button("Start scan", type="primary", width="stretch")
    if mode == "Live network":
        st.caption("Live discovery sends ARP requests only; scope is limited to private/link-local IPv4 networks up to 256 addresses. Unanswered hosts remain unknown.")
        with st.expander("Network diagnostics", expanded=True):
            if active_network and active_network.local_ip:
                st.write(f"Interface: `{active_network.interface_name or active_network.interface}`")
                st.write(f"Local IPv4: `{active_network.local_ip}` · Detected subnet: `{active_network.subnet}`")
                st.write(f"Default gateway: `{active_network.gateway or 'unknown'}`")
                st.write("Method: Scapy Ethernet/ARP")
                st.caption("The target subnet must contain the active local IPv4 address.")
            else:
                st.warning(active_network.message if active_network else "Unable to inspect the active network.")

if run:
    try:
        with st.spinner("Scanning and saving snapshot…"):
            scan_id, scanned, changes = run_scan(
                repo, mode="simulation" if mode == "Simulation" else "live", seed=int(seed), count=count,
                subnet=subnet, timeout=timeout, authorized=authorized, interface=selected_interface,
                missing_threshold=int(threshold),
            )
        st.session_state["scan_notice"] = f"Scan completed: {len(scanned)} device(s). Snapshot {scan_id[:8]} saved."
        st.session_state["scan_diagnostics"] = repo.last_diagnostics.to_dict()
        st.rerun()
    except Exception as exc:
        if getattr(repo, "last_diagnostics", None) is not None:
            st.session_state["scan_diagnostics"] = repo.last_diagnostics.to_dict()
        st.error(f"Scan failed safely: {exc}")

if "scan_notice" in st.session_state:
    st.success(st.session_state.pop("scan_notice"))
if "scan_diagnostics" in st.session_state:
    diagnostic = st.session_state.pop("scan_diagnostics")
    with st.expander("Last scan diagnostics", expanded=True):
        st.write(f"Interface: `{diagnostic.get('interface') or 'not applicable'}`")
        st.write(f"Local IPv4: `{diagnostic.get('local_ip') or 'not applicable'}` · Subnet: `{diagnostic.get('subnet') or 'not applicable'}`")
        st.write(f"Gateway: `{diagnostic.get('gateway') or 'unknown'}` · Responses: `{diagnostic.get('response_count', 0)}`")
        st.write(
            f"Normalized devices: `{diagnostic.get('normalized_device_count', 0)}` · "
            f"Names resolved: `{diagnostic.get('hostname_resolved_count', 0)}`"
        )
        st.write(f"Status: {diagnostic.get('message') or 'completed'}")
        if diagnostic.get("suggestion"):
            st.info(diagnostic["suggestion"])

sessions = repo.scans(limit=100); latest = repo.latest_scan()
current_observations = repo.observations(latest.scan_id) if latest else []
devices = [to_device(o) for o in current_observations]

if page == "Overview":
    if latest:
        metrics = dashboard_metrics(devices)
        cols = st.columns(5)
        for col, label, key in zip(cols,["Observed devices","Online","Offline (thresholded)","Unknown / not observed","IoT devices"],["total","online","offline","unknown","iot"]): col.metric(label, metrics[key])
        time_label = latest.started_at.strftime("%Y-%m-%d %H:%M UTC") if latest.started_at else "Unknown"
        st.caption(f"Latest successful scan: **{time_label}** · mode **{latest.mode}** · source **{latest.source}** · duration **{latest.duration_seconds or 0:.2f}s** · status **{latest.status}**")
        if latest.mode == "simulation": st.info("Simulation data — generated locally; not a measurement of your network.")
        left,right=st.columns([1,1.3])
        with left:
            counts=type_counts(devices)
            if counts: st.plotly_chart(px.pie(names=list(counts),values=list(counts.values()),hole=.55,title="Device types"),width="stretch")
            else: st.info("No records in this scan.")
        with right:
            st.subheader("Recent changes")
            events=repo.changes(latest.scan_id, limit=12)
            if events: st.dataframe(pd.DataFrame([{"Change":e.event_type.replace("_"," ").title(),"Device ID":e.device_id[:8],"Details":e.details,"Time":e.created_at} for e in events]),width="stretch",hide_index=True)
            else: st.caption("No changes recorded for this snapshot.")
    else:
        st.info("No successful scan is stored yet. Start a simulation scan to explore the dashboard without touching a live network.")

elif page == "Devices":
    st.subheader("Devices")
    successful_sessions=[s for s in sessions if s.status=="success"]
    if successful_sessions:
        device_scan_id=st.selectbox("Scan snapshot / date",[s.scan_id for s in successful_sessions],
            format_func=lambda sid: next((f"{s.started_at} · {s.mode} · {s.scan_id[:8]}" for s in successful_sessions if s.scan_id==sid),sid))
        devices=[to_device(o) for o in repo.observations(device_scan_id)]
    if not devices: st.info("Run a scan to populate the device list.")
    else:
        c1,c2,c3,c4=st.columns([2,1,1,1])
        query=c1.text_input("Search IP, hostname, or MAC")
        type_filter=c2.selectbox("Device type",["All"]+sorted({d.device_type for d in devices}))
        source_filter=c3.selectbox("Source",["All"]+sorted({d.discovery_source for d in devices}))
        status_filter=c4.selectbox("Status",["All","online","offline","unknown"])
        filtered=filter_devices(devices,query=query,device_type=type_filter,source=source_filter,status=status_filter)
        table=pd.DataFrame([{ "Device Name":d.hostname or "Unknown","IP address":d.ip_address,"MAC":d.mac_address,"Type":d.device_type,"Status":d.status.value,"Identification method":d.hostname_method or "Not attempted","Identification status":d.hostname_status,"Manufacturer":d.manufacturer,"Discovery source":d.discovery_source,"First seen":d.first_seen,"Last seen":d.last_seen} for d in filtered])
        st.dataframe(table,width="stretch",hide_index=True)
        selected=st.selectbox("Device details",[d.device_id for d in filtered],format_func=lambda i: next((f"{d.hostname or d.ip_address} · {d.ip_address}" for d in filtered if d.device_id==i),i)) if filtered else None
        if selected:
            d=next(x for x in filtered if x.device_id==selected)
            with st.expander("Selected device record",expanded=True):
                st.json(d.to_dict())
                st.caption(f"Hostname: {d.hostname or 'Unknown'} · Identification: {d.hostname_method or 'Not attempted'} ({d.hostname_status})")
        st.caption(f"Showing {len(filtered)} of {len(devices)} observations from this scan. Historical and threshold-derived status is available under History & Changes; exports contain only actual snapshot observations.")

elif page == "Topology":
    st.subheader("Observed device map")
    if devices:
        st.plotly_chart(build_topology(devices,mode=latest.mode),width="stretch")
        st.caption("Lines are simulated or inferred—not measured physical paths. If a router is explicitly observed, it is shown as the anchor; otherwise the center is only a visual map anchor and the gateway is unknown. Host discovery cannot reveal complete physical topology.")
    else: st.info("Run a scan to create a topology view.")

elif page == "History & Changes":
    st.subheader("Scan history")
    if sessions:
        scan_table=pd.DataFrame([{"Started":s.started_at,"Mode":s.mode,"Source":s.source,"Scope":s.scope,"Missing threshold":s.missing_threshold,"Status":s.status,"Devices":s.device_count,"Duration (s)":s.duration_seconds,"Scan ID":s.scan_id} for s in sessions])
        st.dataframe(scan_table,width="stretch",hide_index=True)
        chosen=st.selectbox("Inspect snapshot",[s.scan_id for s in sessions],format_func=lambda sid: next((f"{s.started_at} · {s.mode} · {s.status} · {s.scan_id[:8]}" for s in sessions if s.scan_id==sid),sid))
        obs=repo.observations(chosen); ev=repo.changes(chosen)
        st.write(f"**Snapshot records:** {len(obs)} · **Change events:** {len(ev)}")
        if ev: st.dataframe(pd.DataFrame([{"Event":e.event_type,"Device ID":e.device_id,"Details":e.details,"Created":e.created_at} for e in ev]),width="stretch",hide_index=True)
        else: st.caption("No change events for this scan.")
    else: st.info("No scan sessions yet.")

elif page == "Reports":
    st.subheader("Reports and exports")
    if sessions:
        chosen=st.selectbox("Export snapshot",[s.scan_id for s in sessions],format_func=lambda sid: next((f"{s.started_at} · {s.mode} · {s.device_count} devices · {s.scan_id[:8]}" for s in sessions if s.scan_id==sid),sid))
        csv_data=export_csv(repo,chosen); json_data=export_json(repo,chosen); summary=summary_report(repo,chosen)
        a,b,c=st.columns(3)
        a.download_button("Download CSV",csv_data,file_name=f"netmap-{chosen[:8]}.csv",mime="text/csv",width="stretch")
        b.download_button("Download JSON",json_data,file_name=f"netmap-{chosen[:8]}.json",mime="application/json",width="stretch")
        c.download_button("Download summary JSON",json.dumps(summary,indent=2),file_name=f"netmap-{chosen[:8]}-summary.json",mime="application/json",width="stretch")
        st.json(summary["summary"])
        st.caption("Export contents are read from the selected persisted scan snapshot; an empty snapshot exports a header-only CSV and an empty devices array.")
    else: st.info("Run a scan before exporting a report.")

st.sidebar.markdown("---")
st.sidebar.caption("NetMap IoT · Local SQLite storage · Live ARP requires permission and appropriate interface access")
