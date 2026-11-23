"""Orchestrazione: esegue le scansioni, aggiorna lo stato, applica i rimedi."""

import ipaddress
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import discovery, entities, ha, netinfo, portscan, probes, rules, upnp
from .store import Store

log = logging.getLogger(__name__)

UPNP_ERRORS = {
    "606": "il router non autorizza questa operazione da un dispositivo diverso da quello che ha aperto la porta",
    "714": "l'apertura non esiste più sul router",
}
MAX_INCIDENTS = 200
REPUBLISH_SECONDS = 600


def _now() -> int:
    return int(time.time())


class Engine:
    def __init__(self, store: Store, options: dict):
        self.store = store
        self.options = options
        self.status = {"running": False, "phase": "", "error": None, "next_scan": None}
        self._scan_lock = threading.Lock()
        self._publish_lock = threading.Lock()
        ha.configure(options)

    # ------------------------------------------------------------------ scansione

    def start_scan(self) -> bool:
        if self._scan_lock.locked():
            return False
        threading.Thread(target=self.scan, name="scan", daemon=True).start()
        return True

    def scan(self) -> None:
        if not self._scan_lock.acquire(blocking=False):
            return
        started = time.time()
        self.status.update(running=True, error=None)
        self.publish()
        incidents = []
        try:
            incidents = self._scan()
            self._record(started)
        except Exception as exc:
            log.exception("Scansione fallita")
            self.status["error"] = str(exc)
        finally:
            self.status.update(running=False, phase="")
            self._scan_lock.release()
        self.publish()
        self._announce(incidents)

    def _scan(self) -> list[dict]:
        self.status["phase"] = "Ricerca dei dispositivi"
        nets = netinfo.resolve_networks(self.options.get("networks"))
        if not nets:
            raise RuntimeError("nessuna rete locale individuata: indicala nell'opzione 'networks'")
        hosts: dict[str, dict] = {}
        for net in nets:
            for host in discovery.discover(net):
                hosts.setdefault(host["ip"], host)
        log.info("Reti %s: %d dispositivi accesi", [str(n) for n in nets], len(hosts))

        self.status["phase"] = "Scansione delle porte"
        open_ports = portscan.scan(list(hosts), self.options.get("extra_ports") or [])

        self.status["phase"] = "Verifica dei servizi"
        active = bool(self.options.get("active_probes", True))
        pairs = [(ip, port) for ip, ports in open_ports.items() for port in ports]
        with ThreadPoolExecutor(max_workers=32) as pool:
            infos = list(pool.map(lambda p: probes.probe(p[0], p[1], active), pairs))
        details: dict[str, list] = {ip: [] for ip in hosts}
        for (ip, port), info in zip(pairs, infos):
            details[ip].append({"port": port, "service": portscan.PORTS.get(port, "?"), "info": info})

        self.status["phase"] = "Controllo del router"
        router = upnp.snapshot()
        gateway = netinfo.gateway() or (router.get("igd") or {}).get("host")
        my_ip = netinfo.local_ip()

        self.status["phase"] = "Analisi"
        now = _now()
        with self.store.lock:
            data = self.store.data
            devices = data["devices"]
            baseline_done = data["baseline_done"]
            old_router = data.get("router", {})
            # Fotografia di prima, per riconoscere ciò che è cambiato (gli incidenti).
            old_ports = {k: {p["port"] for p in d.get("ports", [])} for k, d in devices.items()}
            old_maps = {(m["protocol"], m["external_port"]) for m in old_router.get("mappings", [])}

            for dev in devices.values():
                dev["online"] = False
            new_keys = []
            for ip, host in hosts.items():
                key = host.get("mac") or f"ip:{ip}"
                dev = devices.get(key)
                if dev is None:
                    new_keys.append(key)
                    dev = devices[key] = {
                        "key": key, "name": "", "trusted": False, "first_seen": now,
                        # Alla prima scansione tutto è "nuovo": non genera avvisi, si classifica a mano.
                        "needs_review": baseline_done,
                    }
                dev.update(
                    ip=ip, mac=host.get("mac"), online=True, last_seen=now,
                    vendor=host.get("vendor") or dev.get("vendor"),
                    hostname=host.get("hostname") or dev.get("hostname"),
                    ports=sorted(details.get(ip, []), key=lambda e: e["port"]),
                    is_gateway=ip == gateway, is_self=ip == my_ip,
                )
            online = [d for d in devices.values() if d["online"]]
            by_ip = {d["ip"]: d for d in online}

            found = []
            for dev in online:
                found.extend(rules.device_findings(dev, dev.get("needs_review", False)))
            found.extend(rules.router_findings(router, by_ip))
            fresh = self._merge(found, {d["key"] for d in online}, now)

            new_router = {k: v for k, v in router.items() if k != "igd"}
            if router.get("igd"):
                new_router["model"] = " ".join(
                    filter(None, [router["igd"].get("manufacturer"), router["igd"].get("modelName")]))
            new_router["gateway"] = gateway
            new_router["gateway_mac"] = (by_ip.get(gateway) or {}).get("mac") or old_router.get("gateway_mac")
            new_router["behind_nat"] = rules.is_behind_nat(router.get("external_ip"))

            incidents = []
            if baseline_done:
                incidents = self._detect_incidents(
                    now, fresh, new_keys, old_ports, old_maps, old_router, new_router)
                data.setdefault("incidents", []).extend(incidents)
                del data["incidents"][:-MAX_INCIDENTS]

            data["router"] = new_router
            data["networks"] = [str(n) for n in nets]
            data["baseline_done"] = True
            self.store.save()
        return incidents

    def _merge(self, found: list[dict], evaluated: set, now: int) -> list[dict]:
        """Aggiorna i problemi noti; restituisce quelli comparsi con questa scansione."""
        findings = self.store.data["findings"]
        fresh = []
        seen = set()
        for f in found:
            seen.add(f["id"])
            old = findings.get(f["id"])
            if old is None or old["status"] == "resolved":
                f.update(status="open", first_seen=now)
                fresh.append(f)
            else:
                f.update(status=old["status"], first_seen=old["first_seen"])
            f["last_seen"] = now
            findings[f["id"]] = f
        for fid, f in findings.items():
            if fid in seen or f["status"] == "resolved":
                continue
            # Un dispositivo spento non è un problema risolto: si chiude solo ciò che è stato ricontrollato.
            if f["category"] == "router" or f.get("device_key") in evaluated:
                f.update(status="resolved", resolved_at=now)
        return fresh

    # ------------------------------------------------------------------ incidenti

    def _detect_incidents(self, now, fresh, new_keys, old_ports, old_maps, old_router, new_router) -> list[dict]:
        """Un incidente è un cambiamento sospetto tra due scansioni, non uno stato."""
        devices = self.store.data["devices"]
        fresh_by_id = {f["id"]: f for f in fresh}
        covered = set()
        out = []

        def add(kind, severity, title, detail, key=None, ref=""):
            dev = devices.get(key or "", {})
            out.append({
                "id": f"{kind}:{key or 'router'}:{ref}:{now}", "ts": now, "type": kind, "severity": severity,
                "title": title, "detail": detail, "device_key": key, "ip": dev.get("ip"),
                "device": entities.label(dev) if dev else None, "acknowledged": False,
            })

        for key in new_keys:
            dev = devices[key]
            covered.add(f"new-device:{key}")
            covered.update(i for i in fresh_by_id if i.split(":", 1)[-1].startswith(key + ":"))
            ports = ", ".join(str(p["port"]) for p in dev.get("ports", [])) or "nessuna"
            add("nuovo_dispositivo", "medium", "Nuovo dispositivo collegato alla rete",
                f"{entities.label(dev)} ({dev['ip']}, MAC {dev.get('mac') or 'sconosciuto'}) non era mai stato visto. "
                f"Porte aperte: {ports}.", key)

        for key, dev in devices.items():
            if key in new_keys or not dev.get("online") or key not in old_ports:
                continue
            for entry in dev.get("ports", []):
                port = entry["port"]
                if port in old_ports[key]:
                    continue
                finding = fresh_by_id.get(f"port:{key}:{port}")
                covered.add(f"port:{key}:{port}")
                add("nuovo_servizio", finding["severity"] if finding else "low",
                    f"Nuovo servizio in ascolto: porta {port} ({entry['service']})",
                    f"{entities.label(dev)} ({dev['ip']}) ha aperto la porta {port}, che nella scansione precedente era chiusa."
                    + (f" {finding['title']}." if finding else ""), key, str(port))

        for m in new_router.get("mappings", []):
            if (m["protocol"], m["external_port"]) in old_maps:
                continue
            fid = f"upnp-map:{m['protocol']}:{m['external_port']}"
            covered.add(fid)
            target = next((d for d in devices.values() if d.get("ip") == m["internal_client"] and d.get("online")), None)
            add("porta_esposta", (fresh_by_id.get(fid) or {}).get("severity", "high"),
                f"Nuova porta aperta verso Internet: {m['external_port']}/{m['protocol']}",
                f"Il router ora inoltra la porta {m['external_port']}/{m['protocol']} a "
                f"{entities.label(target) if target else m['internal_client']} "
                f"({m['internal_client']}:{m['internal_port']})"
                + (f", descrizione: {m['description']}" if m.get("description") else "") + ".",
                target["key"] if target else None, f"{m['protocol']}{m['external_port']}")

        old_mac, new_mac = old_router.get("gateway_mac"), new_router.get("gateway_mac")
        if old_mac and new_mac and old_mac != new_mac and old_router.get("gateway") == new_router.get("gateway"):
            add("router_cambiato", "critical", "L'indirizzo fisico del router è cambiato",
                f"All'indirizzo {new_router.get('gateway')} ora risponde il MAC {new_mac} invece di {old_mac}. "
                "Se non hai sostituito il router, un dispositivo potrebbe starsi spacciando per lui (ARP spoofing).",
                ref="mac")

        if not old_router.get("available") and new_router.get("available") and "available" in old_router:
            covered.add("upnp-enabled")
            add("upnp_attivato", "medium", "UPnP è stato attivato sul router",
                "Nella scansione precedente UPnP non rispondeva: ora qualunque dispositivo può aprire porte verso Internet.",
                ref="upnp")

        # Falle gravi comparse senza che sia cambiata una porta (es. un servizio che ora accetta chiunque).
        for fid, f in fresh_by_id.items():
            if fid in covered or f["severity"] not in ("critical", "high"):
                continue
            add("nuova_falla", f["severity"], f"Nuova falla: {f['title']}", f["detail"], f.get("device_key"), fid)
        return out

    def _announce(self, incidents: list[dict]) -> None:
        for incident in incidents:
            log.warning("Incidente: %s - %s", incident["title"], incident["detail"])
            ha.fire_event("sentinella_incidente", {
                "tipo": incident["type"], "gravita": entities.SEV_IT[incident["severity"]],
                "titolo": incident["title"], "dettaglio": incident["detail"],
                "dispositivo": incident.get("device"), "ip": incident.get("ip"),
            })
        if self.options.get("notify", True):
            ha.notify([f"{i['title']}" + (f" ({i['device']})" if i.get("device") else "") for i in incidents])

    def acknowledge_incident(self, incident_id: str | None) -> None:
        """Segna come verificato un incidente (o tutti, senza id)."""
        with self.store.lock:
            hits = [i for i in self.store.data.get("incidents", [])
                    if incident_id is None or i["id"] == incident_id]
            if incident_id is not None and not hits:
                raise KeyError(incident_id)
            for incident in hits:
                incident["acknowledged"] = True
            self.store.save()
        self.publish_async()

    # ------------------------------------------------------------------ Home Assistant

    def publish(self) -> None:
        # Un errore qui non deve mai fermare le scansioni: lo si registra e lo si mostra nel pannello.
        with self._publish_lock:
            try:
                with self.store.lock:
                    missing = [i["title"] for i in rules.ROUTER_CHECKLIST
                               if not self.store.data["checklist"].get(i["id"])]
                    status = {**self.status, "checklist_total": len(rules.ROUTER_CHECKLIST),
                              "checklist_missing": missing}
                    items = entities.build(self.store.data, status, bool(self.options.get("device_entities", True)))
                ha.publish(items)
            except Exception as exc:
                log.exception("Pubblicazione verso Home Assistant non riuscita")
                ha.status["error"] = f"errore interno: {exc}"

    def publish_async(self) -> None:
        threading.Thread(target=self.publish, name="publish", daemon=True).start()

    def republish_forever(self) -> None:
        """Ripubblica periodicamente: con il canale API gli stati si perdono al riavvio di Home Assistant."""
        while True:
            time.sleep(REPUBLISH_SECONDS)
            if not self.status["running"]:
                self.publish()

    def _record(self, started: float) -> None:
        with self.store.lock:
            data = self.store.data
            data["scans"].append({
                "ts": int(started), "duration": round(time.time() - started, 1),
                "devices": sum(1 for d in data["devices"].values() if d["online"]),
                "counts": entities.counts(data),
            })
            del data["scans"][:-100]
            self.store.save()

    def run_forever(self) -> None:
        time.sleep(5)
        while True:
            self.scan()
            interval = max(1, int(self.options.get("scan_interval_hours", 6))) * 3600
            self.status["next_scan"] = _now() + interval
            time.sleep(interval)

    # ------------------------------------------------------------------ interventi

    def set_finding_status(self, fid: str, status: str) -> None:
        with self.store.lock:
            finding = self.store.data["findings"].get(fid)
            if not finding or status not in ("open", "ignored"):
                raise KeyError(fid)
            finding["status"] = status
            self.store.save()
        self.publish_async()

    def update_device(self, key: str, name=None, trusted=None) -> None:
        with self.store.lock:
            dev = self.store.data["devices"].get(key)
            if not dev:
                raise KeyError(key)
            if name is not None:
                dev["name"] = str(name).strip()[:60]
            if trusted is not None:
                dev["trusted"] = bool(trusted)
                dev["needs_review"] = False
                finding = self.store.data["findings"].get(f"new-device:{key}")
                if finding and finding["status"] != "resolved":
                    finding.update(status="resolved", resolved_at=_now())
            self.store.save()
        self.publish_async()

    def forget_device(self, key: str) -> None:
        with self.store.lock:
            data = self.store.data
            dev = data["devices"].get(key)
            if not dev:
                raise KeyError(key)
            if dev.get("online"):
                raise ValueError("il dispositivo è ancora in rete")
            del data["devices"][key]
            for fid in [i for i, f in data["findings"].items() if f.get("device_key") == key]:
                del data["findings"][fid]
            self.store.save()
        threading.Thread(target=ha.remove, args=("binary_sensor", entities.device_entity_id(key)),
                         daemon=True).start()
        self.publish_async()

    def set_checklist(self, item_id: str, done: bool) -> None:
        if item_id not in {i["id"] for i in rules.ROUTER_CHECKLIST}:
            raise KeyError(item_id)
        with self.store.lock:
            self.store.data["checklist"][item_id] = bool(done)
            self.store.save()
        self.publish_async()

    def apply_action(self, fid: str) -> str:
        """Esegue il rimedio automatico associato a un problema (dopo conferma dell'utente)."""
        with self.store.lock:
            finding = self.store.data["findings"].get(fid)
            action = dict((finding or {}).get("action") or {})
        if not finding or finding["status"] == "resolved" or action.get("type") != "upnp_delete":
            raise KeyError(fid)
        igd = upnp.find_gateway()
        if not igd:
            raise RuntimeError("il router non risponde più via UPnP: chiudi la porta dal suo pannello")
        try:
            upnp.delete_mapping(igd, action["external_port"], action["protocol"], action.get("remote_host", ""))
        except upnp.UpnpError as exc:
            reason = UPNP_ERRORS.get(str(exc), f"errore UPnP {exc}")
            raise RuntimeError(f"Il router ha rifiutato la chiusura: {reason}. Chiudila dal pannello del router.") from exc
        # Si rilegge l'elenco dal router: il problema si chiude solo se l'apertura è davvero sparita.
        still_there = any(
            m["external_port"] == action["external_port"] and m["protocol"] == action["protocol"]
            for m in upnp.list_mappings(igd))
        with self.store.lock:
            if still_there:
                raise RuntimeError("Il router ha accettato la richiesta ma l'apertura è ancora presente: chiudila dal suo pannello.")
            finding.update(status="resolved", resolved_at=_now())
            router = self.store.data.get("router", {})
            router["mappings"] = [
                m for m in router.get("mappings", [])
                if not (m["external_port"] == action["external_port"] and m["protocol"] == action["protocol"])]
            self.store.save()
        log.info("Chiusa la porta %s/%s via UPnP", action["external_port"], action["protocol"])
        self.publish_async()
        return f"Porta {action['external_port']}/{action['protocol']} chiusa."

    # ------------------------------------------------------------------ vista per l'interfaccia

    def snapshot(self) -> dict:
        with self.store.lock:
            data = self.store.data
            order = {s: i for i, s in enumerate(rules.SEVERITIES)}
            findings = sorted(data["findings"].values(),
                              key=lambda f: (order[f["severity"]], -f["first_seen"]))
            devices = sorted(data["devices"].values(),
                             key=lambda d: (not d["online"], ipaddress.ip_address(d["ip"])))
            return {
                "status": dict(self.status),
                "ha": dict(ha.status),
                "counts": entities.counts(data),
                "score": entities.score(data),
                "findings": findings,
                "devices": devices,
                "incidents": list(reversed(data.get("incidents", []))),
                "router": data["router"],
                "checklist": [{**item, "done": bool(data["checklist"].get(item["id"]))}
                              for item in rules.ROUTER_CHECKLIST],
                "scans": data["scans"][-30:],
                "networks": data["networks"],
            }
