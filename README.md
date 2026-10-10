# NetMap IoT — Device Discovery and Network Topology Mapping

NetMap IoT is a local Streamlit demonstration application for comparing **offline deterministic simulation** with narrowly scoped, explicitly authorized local ARP discovery. Both use one normalized device schema and the same SQLite scan-snapshot/reporting pipeline.

## Features

- **Simulation mode:** reproducible virtual devices (router, endpoints, printers, servers, smartphones, and IoT nodes) generated from a user-selected seed; never presented as live measurements.
- **Live mode:** Scapy ARP discovery on one explicitly entered private or IPv4 link-local subnet, capped at 256 addresses. There is no public-range, arbitrary-target, stealth, credential, or exploit scanning.
- Device records with IP, optional MAC/hostname/manufacturer, type, status, discovery source, hostname identification method/status, timestamps, and stable ID.
- Bounded hostname identification using existing metadata first and reverse DNS second; unresolved names remain `Unknown`.
- SQLite persistence for scan sessions, per-scan observations, and change events.
- Dashboard, device search/filter, Plotly map, scan history, CSV/JSON exports, and summary report.
- Missing observations remain **unknown** until a configurable number of consecutive successful scans omit a device; the change log records missing status when the threshold is reached.

## Architecture

```text
app.py                         Streamlit UI and navigation
config/settings.py             Defaults and scope limits
core/device_model.py           Shared normalized Device model
core/change_detector.py        Snapshot comparison and missing policy
discovery/simulated.py         Deterministic offline generator
discovery/local_network.py     Validated Scapy ARP discovery
database/db.py                 SQLite/SQLAlchemy setup
database/repository.py         Scan, observation, and change persistence
services/scan_service.py       Scan orchestration and deduplication
services/report_service.py     CSV/JSON/summary serialization
ui/dashboard.py                Metric calculations
ui/devices.py                  Search/filter logic
ui/topology.py                 Interactive Plotly topology display
tests/                         Automated verification
```

## Prerequisites

- Python **3.12** recommended (verified in this environment).
- Simulation: no Internet, raw-socket privileges, or packet-capture driver needed after dependencies are installed.
- Live discovery: a directly attached IPv4 LAN, Scapy, correct network interface access, and (on Windows) Npcap. Administrator/root rights may be required depending on OS/interface. Hostname identification does not prove device ownership or operating system. Reverse DNS names are DNS records, not necessarily the computer's advertised name. NetBIOS and mDNS are optional future enrichment methods and are not required for ARP discovery.

## Install and run

### Windows 11 (PowerShell)

```powershell
cd NetMap-IoT
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

For live discovery on Windows, install Npcap separately and permit the required interface access. Start with a subnet belonging to a network you administer. Do not select public or third-party networks. The app requires the explicit authorization checkbox and refuses non-private/public or oversized scopes.

### Linux / macOS

```bash
cd NetMap-IoT
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

Open the local URL shown by Streamlit (normally `http://localhost:8501`). The SQLite database is created at `data/netmap.sqlite3` on first start. Override its location if needed by setting `NETMAP_DATABASE_URL`, e.g. `sqlite:////absolute/path/netmap.sqlite3`.

### Streamlit Community Cloud

The app can be deployed with `app.py` as the main file and `requirements.txt` as the dependency file. Cloud execution is suitable for the simulation dashboard, persisted data within the running instance, topology visualization, history, and exports. Community Cloud does not run inside your laptop's Wi-Fi or hotspot network, so live ARP discovery cannot enumerate devices on your local network from the hosted app. SQLite storage on cloud infrastructure is local to the running instance and should not be treated as durable long-term history; use a managed external database only as a separate future deployment decision.

## Demonstrate simulation mode

1. Open the app and select **Simulation** in the sidebar.
2. Keep or change the deterministic seed and click **Start scan**.
3. Visit **Overview**, **Devices**, **Topology**, **History & Changes**, and **Reports**.
4. Repeat with the same seed to verify a repeatable virtual network. A different seed changes selected virtual attributes; simulation output remains explicitly identified.
5. Download a persisted snapshot as CSV/JSON. Scans survive application restarts.

## Authorized live-network setup

1. Confirm you own/administer the LAN and have permission to probe it.
2. Select **Live network**. NetMap refreshes the active IPv4 interface, local address, subnet, and gateway before each scan. If multiple suitable interfaces are available, choose the authorized interface shown in the selector.
3. Confirm or enter the target subnet in CIDR notation (e.g. `192.168.1.0/24`), check the authorization box, and scan.
4. If the host cannot access ARP/raw sockets, use an appropriately configured interface/driver/permissions or stay in simulation mode. NetMap does not fall back to scanning arbitrary addresses.
5. Review the **Network diagnostics** panel for the selected interface, local IPv4 address, subnet, gateway, ARP response count, normalized device count, and resolved-name count.

When the laptop changes networks, the subnet field is synchronized to the newly detected interface/network identity. A valid manual subnet override is preserved while that same network remains selected; a subnet from a previous network is not silently reused. If network detection fails, no hardcoded subnet is presented as detected and the target must be supplied only after valid local configuration is available.

Unanswered ARP requests do **not** mean a host is offline. In the current implementation they are absent from the snapshot; the change log marks a device missing only after the configured count of consecutive successful scans. A normal ARP scan does not expose all network paths, VLANs, switch ports, or physical topology.

## Tests

```bash
python -m pip install -r requirements.txt
pytest -q
```

Tests use temporary in-memory SQLite databases and do not scan any network. They cover deterministic simulation, schema validation, duplicate handling, persistence, snapshot comparison and missing thresholds, subnet rejection, empty exports, and scan errors.

## Troubleshooting

- **`Scapy is not installed`**: activate the project virtual environment and run `pip install -r requirements.txt`.
- **Npcap/interface/permission error**: verify Npcap is installed and the correct interface is available; live ARP can require elevated rights. Simulation requires none.
- **Invalid or too-large subnet**: use an RFC1918 private IPv4 or link-local range with no more than 256 total addresses, typically `/24` or narrower.
- **No live devices found**: wireless client isolation, VLANs, host firewalls, sleep, or ARP filtering can prevent responses. Empty scan results are valid and do not mark hosts offline.
- **Device found but name is Unknown**: hostname identification is separate from ARP discovery. Reverse DNS may have no PTR record, and the device may not advertise a local name. The IP/MAC observation remains valid.
- **Port in use**: run `streamlit run app.py --server.port 8502`.
- **Reset demo data**: stop the app and remove `data/netmap.sqlite3` (this permanently deletes local scan history).

## Known limitations and verification record

- The app is a monitoring/demo tool, not a complete network inventory platform.
- Live discovery is IPv4 ARP-only, capped at 256 addresses, and requires a same-L2 segment. Hostname enrichment uses bounded, cached reverse-DNS lookups after discovery; unavailable fields remain null/unknown. NetBIOS/mDNS are not required and are not assumed to be available.
- Topology lines are simulated or inferred; physical network links are not observed.
- Missing/offline information is conservative and requires repeated successful scans. Live tests require a user-controlled authorized LAN and platform-specific packet capture permissions; they were not performed in this environment.
- Automated tests and a local Streamlit HTTP smoke check are performed during delivery; consult the completion summary for the exact results.
