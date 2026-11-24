"""Opzioni dell'add-on (lette da /data/options.json, scritto dal Supervisor)."""

import json
import os
from pathlib import Path

DATA_DIR = Path(os.environ.get("SENTINELLA_DATA", "/data"))
DEV = os.environ.get("SENTINELLA_DEV") == "1"
PORT = int(os.environ.get("SENTINELLA_PORT") or (DEV and os.environ.get("PORT")) or 8099)

# Il proxy ingress di Home Assistant raggiunge l'add-on sempre da questo indirizzo.
INGRESS_PROXY = "172.30.32.2"

DEFAULTS = {
    "scan_interval_hours": 6,
    "networks": [],
    "extra_ports": [],
    "active_probes": True,
    "notify": True,
    "ha_links": True,
    "deep_scan": False,
    "language": "auto",
    "monitor_zigbee": True,
    "monitor_zwave": True,
    "monitor_matter": True,
    "monitor_bluetooth": True,
    "monitor_mqtt": True,
    "monitor_access": True,
    "zigbee2mqtt_in_zigbee": True,
    "health_interval_minutes": 30,
    "battery_threshold": 20,
    "silent_hours": 48,
}


def load_options() -> dict:
    options = dict(DEFAULTS)
    try:
        options.update(json.loads((DATA_DIR / "options.json").read_text(encoding="utf-8")))
    except (OSError, ValueError):
        pass
    return options
