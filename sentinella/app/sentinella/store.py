"""Stato persistente su file JSON (/data/state.json)."""

import json
import os
import threading
from pathlib import Path

EMPTY = {
    "devices": {},      # chiave (MAC oppure "ip:x.x.x.x") -> dispositivo
    "findings": {},     # id -> problema
    "incidents": [],    # cambiamenti sospetti tra una scansione e l'altra
    "checklist": {},   # id voce -> True se confermata dall'utente
    "router": {},       # ultimo stato UPnP
    "scans": [],        # cronologia sintetica
    "baseline_done": False,
    "networks": [],
}


class Store:
    def __init__(self, data_dir: Path):
        self.path = Path(data_dir) / "state.json"
        self.lock = threading.RLock()
        self.data = json.loads(json.dumps(EMPTY))
        try:
            self.data.update(json.loads(self.path.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            pass

    def save(self) -> None:
        with self.lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.data, ensure_ascii=False, indent=1), encoding="utf-8")
            os.replace(tmp, self.path)
