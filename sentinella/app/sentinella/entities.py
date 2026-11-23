"""Entità esposte a Home Assistant: descrizione indipendente dal canale (MQTT o API)."""

import re
from datetime import datetime, timezone

SEV_IT = {"critical": "critico", "high": "alto", "medium": "medio", "low": "basso", "info": "informativo"}
SEV_ORDER = ["critical", "high", "medium", "low", "info"]
MAX_ITEMS = 50  # oltre i 16 KB di attributi Home Assistant smette di registrarli nello storico


def iso(ts) -> str | None:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat() if ts else None


def label(dev: dict) -> str:
    info = dev.get("info") or {}
    return (dev.get("name") or info.get("friendly_name") or dev.get("hostname") or info.get("model")
            or dev.get("vendor") or dev.get("ip") or "?")


def ha_summary(dev: dict) -> dict:
    """Riferimenti a ciò che Home Assistant conosce già di questo dispositivo."""
    link = dev.get("ha") or {}
    devices = link.get("devices", [])
    return {
        "collegato_a_home_assistant": bool(link.get("linked")),
        "dispositivi_ha": [{"nome": d["name"], "id": d["id"], "integrazioni": d["integrations"],
                            "area": d["area"], "trovato_per": d["match"]} for d in devices],
        "integrazioni_ha": sorted({i for d in devices for i in d["integrations"]}),
        "entita_ha": [e for d in devices for e in d["entities"]][:15]
                     + [e["entity_id"] for e in link.get("entities", [])],
    }


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
    return max(0, 100 - penalty)


def _dev_item(dev: dict) -> dict:
    return {"nome": label(dev), "ip": dev.get("ip"), "mac": dev.get("mac"), "produttore": dev.get("vendor"),
            "tipo": (dev.get("info") or {}).get("type_label")}


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
    by_type: dict[str, int] = {}
    for d in online:
        kind = (d.get("info") or {}).get("type_label") or "Non identificato"
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
    checklist_total = status.get("checklist_total", 0)
    checklist_done = sum(1 for v in data.get("checklist", {}).values() if v)

    def where(f):
        dev = by_key.get(f.get("device_key") or "")
        return label(dev) if dev else "router"

    finding_items = [{"gravita": SEV_IT[f["severity"]], "titolo": f["title"], "dove": where(f),
                      "ip": f.get("ip"), "porta": f.get("port")} for f in open_findings[:MAX_ITEMS]]
    incident_items = [{"quando": iso(i["ts"]), "gravita": SEV_IT[i["severity"]], "titolo": i["title"],
                       "dettaglio": i["detail"]} for i in incidents[-MAX_ITEMS:]]
    worst = next((s for s in SEV_ORDER if c[s]), None)
    measurement = {"state_class": "measurement"}

    out = [
        # --- dispositivi
        _sensor("dispositivi_online", "Dispositivi in rete", len(online), "mdi:lan-connect",
                {"dispositivi": [_dev_item(d) for d in online[:MAX_ITEMS]], "per_tipo": by_type},
                unit="dispositivi", **measurement),
        _sensor("dispositivi_domotica", "Dispositivi collegati alla domotica", len(linked), "mdi:home-automation",
                {"dispositivi": [{**_dev_item(d), "integrazioni": ha_summary(d)["integrazioni_ha"]}
                                 for d in linked[:MAX_ITEMS]],
                 "non_collegati": [_dev_item(d) for d in online if not (d.get("ha") or {}).get("linked")][:MAX_ITEMS]},
                unit="dispositivi", **measurement),
        _sensor("dispositivi_noti", "Dispositivi conosciuti", len(devices), "mdi:lan", unit="dispositivi", **measurement),
        _sensor("dispositivi_non_fidati", "Dispositivi non fidati", len(untrusted), "mdi:help-network",
                {"dispositivi": [_dev_item(d) for d in untrusted[:MAX_ITEMS]]}, unit="dispositivi", **measurement),
        _binary("nuovo_dispositivo", "Nuovo dispositivo rilevato", review,
                {"dispositivi": [{**_dev_item(d), "rilevato": iso(d.get("first_seen"))} for d in review[:MAX_ITEMS]]},
                icon="mdi:lan-pending"),
        _sensor("ultimo_dispositivo", "Ultimo dispositivo comparso", label(newest) if newest else None,
                "mdi:new-box",
                {**_dev_item(newest), "rilevato": iso(newest.get("first_seen")), "fidato": bool(newest.get("trusted"))}
                if newest else {}),
        # --- falle
        _sensor("problemi_aperti", "Problemi aperti", sum(c.values()), "mdi:shield-alert",
                {"problemi": finding_items, **{SEV_IT[s]: n for s, n in c.items()}}, unit="problemi", **measurement),
        _sensor("problemi_critici", "Problemi critici", c["critical"], "mdi:alert-octagon", unit="problemi", **measurement),
        _sensor("problemi_alti", "Problemi alti", c["high"], "mdi:alert", unit="problemi", **measurement),
        _sensor("problemi_medi", "Problemi medi", c["medium"], "mdi:alert-outline", unit="problemi", **measurement),
        _sensor("problemi_bassi", "Problemi bassi", c["low"] + c["info"], "mdi:information-outline",
                unit="problemi", **measurement),
        _sensor("gravita_massima", "Gravità massima", SEV_IT[worst] if worst else "nessuna", "mdi:shield-half-full"),
        _binary("falle", "Falle di sicurezza", c["critical"] + c["high"] + c["medium"],
                {"problemi": [i for i in finding_items if i["gravita"] in ("critico", "alto", "medio")]},
                device_class="problem"),
        _sensor("punteggio", "Punteggio di sicurezza", score(data), "mdi:shield-star", unit="%", **measurement),
        # --- incidenti
        _binary("incidente", "Incidente di sicurezza", incidents, {"incidenti": incident_items},
                device_class="safety"),
        _sensor("incidenti", "Incidenti da verificare", len(incidents), "mdi:shield-bug",
                {"incidenti": incident_items}, unit="incidenti", **measurement),
        _sensor("ultimo_incidente", "Ultimo incidente", all_incidents[-1]["title"] if all_incidents else None,
                "mdi:shield-bug-outline",
                {"quando": iso(all_incidents[-1]["ts"]), "gravita": SEV_IT[all_incidents[-1]["severity"]],
                 "dettaglio": all_incidents[-1]["detail"], "verificato": bool(all_incidents[-1].get("acknowledged"))}
                if all_incidents else {}),
        # --- router
        _sensor("porte_esposte", "Porte aperte verso Internet", len(mappings), "mdi:door-open",
                {"porte": [{"porta": f"{m['external_port']}/{m['protocol']}",
                            "verso": f"{m['internal_client']}:{m['internal_port']}",
                            "descrizione": m.get("description", "")} for m in mappings[:MAX_ITEMS]],
                 "nota": "solo aperture UPnP: i port forwarding manuali non sono leggibili"},
                unit="porte", **measurement),
        _binary("upnp", "UPnP attivo sul router", router.get("available"), icon="mdi:router-wireless-settings"),
        _sensor("ip_pubblico", "Indirizzo IP pubblico", router.get("external_ip"), "mdi:ip-network",
                {"dietro_nat_operatore": bool(router.get("behind_nat"))}, entity_category="diagnostic"),
        _sensor("verifiche_router", "Verifiche manuali completate", checklist_done, "mdi:clipboard-check",
                {"totale": checklist_total, "mancanti": status.get("checklist_missing", [])}, **measurement),
        # --- scansione
        _sensor("ultima_scansione", "Ultima scansione", iso(last_scan["ts"]) if last_scan else None, None,
                {"reti": data.get("networks", []), "errore": status.get("error")},
                device_class="timestamp", entity_category="diagnostic"),
        _sensor("durata_scansione", "Durata ultima scansione", last_scan["duration"] if last_scan else None,
                "mdi:timer-outline", unit="s", device_class="duration", entity_category="diagnostic", **measurement),
        _binary("scansione_in_corso", "Scansione in corso", status.get("running"),
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
                device_entity_id(dev["key"]), "In rete", dev.get("online"),
                # "sorgente" serve a riconoscere le proprie entità quando si rilegge il registro di Home Assistant.
                {"sorgente": "sentinella", "ip": dev.get("ip"), "mac": dev.get("mac"),
                 "mac_privato": bool(info.get("private_mac")),
                 "produttore": info.get("manufacturer") or dev.get("vendor"),
                 "hostname": dev.get("hostname"), "tipo": info.get("type_label"),
                 "modello": info.get("model"), "nome_rilevato": info.get("friendly_name"),
                 "sistema_operativo": info.get("os"), "firmware": info.get("firmware"),
                 "nome_netbios": info.get("netbios"), "servizi_annunciati": info.get("services", []),
                 "fidato": bool(dev.get("trusted")), "router": bool(dev.get("is_gateway")),
                 "porte_aperte": [" ".join(filter(None, [str(p["port"]), p["service"], p.get("info", {}).get("product")]))
                                  for p in dev.get("ports", [])],
                 "problemi_aperti": open_by_device.get(dev["key"], 0),
                 **ha_summary(dev),
                 "prima_volta": iso(dev.get("first_seen")), "ultima_volta": iso(dev.get("last_seen"))},
                device_class="connectivity",
                device={"key": dev["key"], "name": label(dev), "mac": dev.get("mac"),
                        "vendor": info.get("manufacturer") or dev.get("vendor"), "model": info.get("model")}))
    return out
