"""Central application configuration."""
from __future__ import annotations
import os
from pathlib import Path

APP_NAME = "NetMap IoT"
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB = PROJECT_ROOT / "data" / "netmap.sqlite3"
DATABASE_URL = os.getenv("NETMAP_DATABASE_URL", f"sqlite:///{DEFAULT_DB.as_posix()}")
DEFAULT_SIMULATION_SEED = 20261010
DEFAULT_SCAN_TIMEOUT = 1.5
DEFAULT_MISSING_THRESHOLD = 2
MAX_LIVE_HOSTS = 256
ALLOWED_LIVE_NETWORKS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16")
