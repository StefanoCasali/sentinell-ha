"""Entità esposte a Home Assistant: descrizione indipendente dal canale (MQTT o API).

Gli identificativi (`id`) e le chiavi degli attributi sono stabili e non
dipendono dalla lingua: automazioni e plance non si rompono cambiando lingua.
Nomi delle entità e valori testuali seguono invece la lingua corrente.
"""

import math
import re
from datetime import datetime, timezone

from .i18n import L, t

SEV_LABELS = {
    "critical": L("critico", "critical"), "high": L("alto", "high"), "medium": L("medio", "medium"),
    "low": L("basso", "low"), "info": L("informativo", "info"),
}
SEV_ORDER = ["critical", "high", "medium", "low", "info"]
MAX_ITEMS = 50  # oltre i 16 KB di attributi Home Assistant smette di registrarli nello storico


def sev(severity: str) -> str:
    return str(SEV_LABELS[severity])


def iso(ts) -> str | None:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat() if ts else None


def label(dev: dict) -> str:
    info = dev.get("info") or {}
    return (dev.get("name") or info.get("friendly_name") or dev.get("hostname") or info.get("model")
            or dev.get("vendor") or dev.get("ip") or "?")


def slug(key: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", key.lower()).strip("_")


def device_entity_id(key: str) -> str:
    return f"dispositivo_{slug(key)}"


def counts(data: dict) -> dict:
    out = {s: 0 for s in SEV_ORDER}
    for f in data["findings"].values():
        if f["status"] == "open":
            out[f["severity"]] += 1
    return out


def active_incidents(data: dict) -> list[dict]:
    return [i for i in data.get("incidents", []) if not i.get("acknowledged")]


def score(data: dict) -> int:
    """Punteggio 0-100: parte da 100 e scende con falle aperte, incidenti e dispositivi non classificati."""
    c = counts(data)
    untrusted = sum(1 for d in data["devices"].values() if d.get("online") and not d.get("trusted"))
    penalty = c["critical"] * 25 + c["high"] * 12 + c["medium"] * 5 + c["low"]
    penalty += min(15, untrusted * 3) + len(active_incidents(data)) * 5
    # Curva decrescente: ogni problema in più pesa un po' meno, così il punteggio resta leggibile
    # anche su reti con molte segnalazioni invece di schiacciarsi subito a zero.
    return round(100 * math.exp(-penalty / 70))


def ha_summary(dev: dict) -> dict:
    """Riferimenti a ciò che Home Assistant conosce già di questo dispositivo."""
    link = dev.get("ha") or {}
    devices = link.get("devices", [])
    return {
        "linked_to_home_assistant": bool(link.get("linked")),
        "ha_devices": [{"name": d["name"], "id": d["id"], "integrations": d["integrations"],
                        "area": d["area"], "matched_by": d["match"]} for d in devices],
        "ha_integrations": sorted({i for d in devices for i in d["integrations"]}),
        "ha_entities": [e for d in devices for e in d["entities"]][:15]
                       + [e["entity_id"] for e in link.get("entities", [])],
    }


def _dev_item(dev: dict) -> dict:
    return {"name": label(dev), "ip": dev.get("ip"), "mac": dev.get("mac"), "vendor": dev.get("vendor"),
            "type": (dev.get("info") or {}).get("type_label")}


def _sensor(eid, name, state, icon, attrs=None, **extra):
    return {"domain": "sensor", "id": eid, "name": name, "state": state, "icon": icon,
            "attributes": attrs or {}, **extra}


def _binary(eid, name, state, attrs=None, **extra):
    return {"domain": "binary_sensor", "id": eid, "name": name, "state": bool(state),
            "attributes": attrs or {}, **extra}


def build(data: dict, status: dict, per_device: bool = True) -> list[dict]:
    devices = list(data["devices"].values())
    online = [d for d in devices if d.get("online")]
    untrusted = [d for d in online if not d.get("trusted")]
    review = [d for d in devices if d.get("needs_review")]
    linked = [d for d in online if (d.get("ha") or {}).get("linked")]
    unidentified = t("Non identificato", "Unidentified")
    by_type: dict[str, int] = {}
    for d in online:
        kind = (d.get("info") or {}).get("type_label") or unidentified
        by_type[kind] = by_type.get(kind, 0) + 1
    by_key = data["devices"]
    c = counts(data)
    open_findings = sorted((f for f in data["findings"].values() if f["status"] == "open"),
                           key=lambda f: SEV_ORDER.index(f["severity"]))
    incidents = active_incidents(data)
    all_incidents = data.get("incidents", [])
    router = data.get("router", {})
    mappings = router.get("mappings", [])
    last_scan = data["scans"][-1] if data["scans"] else None
    newest = max(devices, key=lambda d: d.get("first_seen", 0), default=None)
    last_incident = all_incidents[-1] if all_incidents else None
    checklist_done = sum(1 for v in data.get("checklist", {}).values() if v)

    def where(f):
        dev = by_key.get(f.get("device_key") or "")
        return label(dev) if dev else "router"

    finding_items = [{"severity": f["severity"], "title": f["title"], "where": where(f),
                      "ip": f.get("ip"), "port": f.get("port")} for f in open_findings[:MAX_ITEMS]]
    incident_items = [{"when": iso(i["ts"]), "severity": i["severity"], "title": i["title"],
                       "detail": i["detail"]} for i in incidents[-MAX_ITEMS:]]
    worst = next((s for s in SEV_ORDER if c[s]), None)
    measurement = {"state_class": "measurement"}
    u_dev, u_find = t("dispositivi", "devices"), t("problemi", "findings")

    out = [
        # --- dispositivi
        _sensor("dispositivi_online", t("Dispositivi in rete", "Devices online"), len(online), "mdi:lan-connect",
                {"devices": [_dev_item(d) for d in online[:MAX_ITEMS]], "by_type": by_type},
                unit=u_dev, **measurement),
        _sensor("dispositivi_domotica", t("Dispositivi collegati alla domotica", "Devices linked to the smart home"),
                len(linked), "mdi:home-automation",
                {"devices": [{**_dev_item(d), "integrations": ha_summary(d)["ha_integrations"]}
                             for d in linked[:MAX_ITEMS]],
                 "not_linked": [_dev_item(d) for d in online if not (d.get("ha") or {}).get("linked")][:MAX_ITEMS]},
                unit=u_dev, **measurement),
        _sensor("dispositivi_noti", t("Dispositivi conosciuti", "Known devices"), len(devices), "mdi:lan",
                unit=u_dev, **measurement),
        _sensor("dispositivi_non_fidati", t("Dispositivi non fidati", "Untrusted devices"), len(untrusted),
                "mdi:help-network", {"devices": [_dev_item(d) for d in untrusted[:MAX_ITEMS]]},
                unit=u_dev, **measurement),
        _binary("nuovo_dispositivo", t("Nuovo dispositivo rilevato", "New device detected"), review,
                {"devices": [{**_dev_item(d), "detected": iso(d.get("first_seen"))} for d in review[:MAX_ITEMS]]},
                icon="mdi:lan-pending"),
        _sensor("ultimo_dispositivo", t("Ultimo dispositivo comparso", "Latest device seen"),
                label(newest) if newest else None, "mdi:new-box",
                {**_dev_item(newest), "detected": iso(newest.get("first_seen")), "trusted": bool(newest.get("trusted"))}
                if newest else {}),
        # --- falle
        _sensor("problemi_aperti", t("Problemi aperti", "Open findings"), sum(c.values()), "mdi:shield-alert",
                {"findings": finding_items, **c}, unit=u_find, **measurement),
        _sensor("problemi_critici", t("Problemi critici", "Critical findings"), c["critical"], "mdi:alert-octagon",
                unit=u_find, **measurement),
        _sensor("problemi_alti", t("Problemi alti", "High findings"), c["high"], "mdi:alert",
                unit=u_find, **measurement),
        _sensor("problemi_medi", t("Problemi medi", "Medium findings"), c["medium"], "mdi:alert-outline",
                unit=u_find, **measurement),
        _sensor("problemi_bassi", t("Problemi bassi", "Low findings"), c["low"] + c["info"],
                "mdi:information-outline", unit=u_find, **measurement),
        _sensor("gravita_massima", t("Gravità massima", "Highest severity"),
                sev(worst) if worst else t("nessuna", "none"), "mdi:shield-half-full", {"severity": worst}),
        _binary("falle", t("Falle di sicurezza", "Security vulnerabilities"), c["critical"] + c["high"] + c["medium"],
                {"findings": [i for i in finding_items if i["severity"] in ("critical", "high", "medium")]},
                device_class="problem"),
        _sensor("punteggio", t("Punteggio di sicurezza", "Security score"), score(data), "mdi:shield-star",
                unit="%", **measurement),
        # --- incidenti
        _binary("incidente", t("Incidente di sicurezza", "Security incident"), incidents,
                {"incidents": incident_items}, device_class="safety"),
        _sensor("incidenti", t("Incidenti da verificare", "Incidents to review"), len(incidents), "mdi:shield-bug",
                {"incidents": incident_items}, unit=t("incidenti", "incidents"), **measurement),
        _sensor("ultimo_incidente", t("Ultimo incidente", "Latest incident"),
                last_incident["title"] if last_incident else None, "mdi:shield-bug-outline",
                {"when": iso(last_incident["ts"]), "severity": last_incident["severity"],
                 "type": last_incident["type"], "detail": last_incident["detail"],
                 "acknowledged": bool(last_incident.get("acknowledged"))} if last_incident else {}),
        # --- router
        _sensor("porte_esposte", t("Porte aperte verso Internet", "Ports open to the Internet"), len(mappings),
                "mdi:door-open",
                {"ports": [{"port": f"{m['external_port']}/{m['protocol']}",
                            "to": f"{m['internal_client']}:{m['internal_port']}",
                            "description": m.get("description", "")} for m in mappings[:MAX_ITEMS]],
                 "note": t("solo aperture UPnP: i port forwarding manuali non sono leggibili",
                           "UPnP forwards only: manual port forwards cannot be read")},
                unit=t("porte", "ports"), **measurement),
        _binary("upnp", t("UPnP attivo sul router", "UPnP enabled on the router"), router.get("available"),
                icon="mdi:router-wireless-settings"),
        _sensor("ip_pubblico", t("Indirizzo IP pubblico", "Public IP address"), router.get("external_ip"),
                "mdi:ip-network", {"behind_isp_nat": bool(router.get("behind_nat"))}, entity_category="diagnostic"),
        _sensor("verifiche_router", t("Verifiche manuali completate", "Manual checks completed"), checklist_done,
                "mdi:clipboard-check",
                {"total": status.get("checklist_total", 0), "missing": status.get("checklist_missing", [])},
                **measurement),
        # --- scansione
        _sensor("ultima_scansione", t("Ultima scansione", "Last scan"), iso(last_scan["ts"]) if last_scan else None,
                None, {"networks": data.get("networks", []), "error": status.get("error")},
                device_class="timestamp", entity_category="diagnostic"),
        _sensor("durata_scansione", t("Durata ultima scansione", "Last scan duration"),
                last_scan["duration"] if last_scan else None, "mdi:timer-outline", unit="s",
                device_class="duration", entity_category="diagnostic", **measurement),
        _binary("scansione_in_corso", t("Scansione in corso", "Scan in progress"), status.get("running"),
                device_class="running", entity_category="diagnostic"),
    ]

    if per_device:
        open_by_device: dict[str, int] = {}
        for f in open_findings:
            if f.get("device_key"):
                open_by_device[f["device_key"]] = open_by_device.get(f["device_key"], 0) + 1
        for dev in devices:
            info = dev.get("info") or {}
            out.append(_binary(
                device_entity_id(dev["key"]), t("In rete", "Online"), dev.get("online"),
                # "managed_by" serve a riconoscere le proprie entità quando si rilegge il registro di Home Assistant.
                {"managed_by": "sentinella", "ip": dev.get("ip"), "mac": dev.get("mac"),
                 "private_mac": bool(info.get("private_mac")),
                 "vendor": info.get("manufacturer") or dev.get("vendor"),
                 "hostname": dev.get("hostname"), "type": info.get("type_label"),
                 "model": info.get("model"), "detected_name": info.get("friendly_name"),
                 "operating_system": info.get("os"), "firmware": info.get("firmware"),
                 "netbios_name": info.get("netbios"), "announced_services": info.get("services", []),
                 "trusted": bool(dev.get("trusted")), "router": bool(dev.get("is_gateway")),
                 "open_ports": [" ".join(filter(None, [str(p["port"]), p["service"], p.get("info", {}).get("product")]))
                                for p in dev.get("ports", [])],
                 "open_findings": open_by_device.get(dev["key"], 0),
                 **ha_summary(dev),
                 "first_seen": iso(dev.get("first_seen")), "last_seen": iso(dev.get("last_seen"))},
                device_class="connectivity",
                device={"key": dev["key"], "name": label(dev), "mac": dev.get("mac"),
                        "vendor": info.get("manufacturer") or dev.get("vendor"), "model": info.get("model")}))
    return out
