"""Analisi delle reti della domotica: Zigbee, Z-Wave, Matter, Bluetooth, MQTT.

I dispositivi non vengono interrogati direttamente: si parte da ciò che Home
Assistant conosce (registro letto da `halink`) e si controlla la loro salute:
chi non risponde, chi tace da troppo, batterie, segnale, aggiornamenti.
Un problema è uno stato che persiste; un incidente è un cambiamento tra un
controllo e il successivo.
"""

from .halink import is_ours
from .i18n import L, t

NETWORKS = {
    "zigbee": L("Zigbee", "Zigbee"), "zwave": L("Z-Wave", "Z-Wave"), "matter": L("Matter", "Matter"),
    "bluetooth": L("Bluetooth", "Bluetooth"), "mqtt": L("MQTT", "MQTT"),
}
ZIGBEE_INTEGRATIONS = {"zha", "deconz"}
BLE_INTEGRATIONS = {
    "bthome", "xiaomi_ble", "switchbot", "govee_ble", "inkbird", "oralb", "ibeacon", "private_ble_device",
    "led_ble", "yalexs_ble", "airthings_ble", "sensorpush", "thermopro", "ruuvitag_ble", "qingping", "moat",
    "mopeka", "tilt_ble", "kegtron", "eq3btsmart", "improv_ble", "sensirion_ble", "aranet", "bluemaestro",
    "leaone", "motionblinds_ble", "snooz", "melnor", "gardena_bluetooth", "husqvarna_automower_ble",
}
WEAK_LQI = 25
WEAK_RSSI = -88
BATTERY_DROP = 30
MAX_INCIDENTS_PER_CHECK = 8


def enabled_networks(options: dict) -> list[str]:
    """Sezioni che l'utente ha scelto di monitorare."""
    return [key for key in NETWORKS if options.get(f"monitor_{key}", True)]


def classify(device: dict, bridges_by_protocol: bool = True) -> str | None:
    """Rete a cui appartiene un dispositivo di Home Assistant (None: nessuna di quelle analizzate).

    Un dispositivo sta in una sola rete. Quelli che arrivano da un bridge MQTT (Zigbee2MQTT,
    Z-Wave JS UI) contano per il loro protocollo radio; con `bridges_by_protocol` spento restano in MQTT.
    """
    idents = [i for i in device.get("identifiers", []) if isinstance(i, (list, tuple)) and len(i) >= 2]
    domains = {str(i[0]) for i in idents} | {str(i) for i in device.get("integrations", [])}
    conns = {str(c[0]) for c in device.get("connections", []) if isinstance(c, (list, tuple)) and c}
    bridged = [str(i[1]).lower() for i in idents if str(i[0]) == "mqtt"]
    z2m = bridges_by_protocol and any(i.startswith("zigbee2mqtt") for i in bridged)
    zwave_mqtt = bridges_by_protocol and any(i.startswith(("zwavejs2mqtt", "zwave-js-ui", "zwave_js_ui")) for i in bridged)
    if z2m or domains & ZIGBEE_INTEGRATIONS or "zigbee" in conns:
        return "zigbee"
    if zwave_mqtt or "zwave_js" in domains:
        return "zwave"
    if "matter" in domains:
        return "matter"
    if "bluetooth" in conns or domains & BLE_INTEGRATIONS:
        return "bluetooth"
    if "mqtt" in domains:
        return "mqtt"
    return None


def _is_bridge(device: dict) -> bool:
    idents = " ".join(str(i[-1]) for i in device.get("identifiers", []) if i).lower()
    model = (device.get("model") or "").lower()
    return "bridge" in idents or "coordinator" in model or "controller" in model and "zwave" in idents


def _record(device: dict, network: str, options: dict, now: int) -> dict:
    h = device.get("h") or {}
    count, unavailable = int(h.get("n") or 0), int(h.get("un") or 0)
    battery = h.get("bat")
    seen = int(h.get("seen") or 0)
    offline = (count > 0 and unavailable == count) or str(h.get("zw") or "").lower() == "dead"
    silent_after = max(1, int(options.get("silent_hours", 48))) * 3600
    # Il silenzio si valuta solo sui dispositivi a batteria: una presa che nessuno usa tace per giorni
    # senza che ci sia nulla di rotto, un sensore a batteria che tace di solito è scarico.
    silent = bool(not offline and battery is not None and seen and now - seen > silent_after)
    threshold = int(options.get("battery_threshold", 20))
    return {
        "id": device["id"], "name": device.get("name") or device["id"], "network": network,
        "manufacturer": device.get("manufacturer") or "", "model": device.get("model") or "",
        "area": device.get("area") or "", "integrations": [i for i in device.get("integrations", []) if i and i != "None"],
        "entities": count, "bridge": _is_bridge(device),
        "battery": battery, "battery_low": bool(h.get("batlow")) or (battery is not None and battery <= threshold),
        "lqi": h.get("lqi"), "rssi": h.get("rssi"), "seen": seen or None,
        "offline": offline, "dead": str(h.get("zw") or "").lower() == "dead", "silent": silent,
        "weak": (h.get("lqi") is not None and h["lqi"] < WEAK_LQI) or (h.get("rssi") is not None and h["rssi"] < WEAK_RSSI),
        "update": bool(h.get("upd")), "permit_join": bool(h.get("pj")),
    }


def _finding(kind: str, rec: dict, severity: str, title: str, detail: str, steps: list[str]) -> dict:
    return {
        "id": f"sh:{kind}:{rec['id']}", "severity": severity, "title": title, "detail": detail,
        "remediation": steps, "category": rec["network"], "network": rec["network"], "scope": "smarthome",
        "port": None, "action": None, "device_key": None, "ip": None,
        "ha_device": {"id": rec["id"], "name": rec["name"]},
    }


def _findings(rec: dict, now: int) -> list[dict]:
    out = []
    name, net = rec["name"], str(NETWORKS[rec["network"]])
    if rec["offline"]:
        if rec["bridge"]:
            out.append(_finding("offline", rec, "high",
                t("Il coordinatore della rete non risponde", "The network coordinator is not responding"),
                t("{name} risulta non disponibile: senza di lui tutta la rete {net} è ferma.",
                  "{name} is unavailable: without it the whole {net} network is down.").format(name=name, net=net),
                [t("Controlla che il coordinatore (chiavetta o bridge) sia collegato e alimentato.",
                   "Check that the coordinator (dongle or bridge) is plugged in and powered."),
                 t("Riavvia l'add-on o l'integrazione che lo gestisce e guarda il suo log.",
                   "Restart the add-on or integration that manages it and check its log.")]))
        else:
            out.append(_finding("offline", rec, "medium",
                t("Dispositivo non raggiungibile", "Device unreachable"),
                (t("Il nodo Z-Wave {name} è segnato come non funzionante (dead).",
                   "Z-Wave node {name} is marked as dead.") if rec["dead"] else
                 t("Tutte le {n} entità di {name} risultano non disponibili in Home Assistant.",
                   "All {n} entities of {name} are unavailable in Home Assistant.")).format(name=name, n=rec["entities"]),
                [t("Controlla alimentazione o batteria del dispositivo.", "Check the device's power supply or battery."),
                 t("Avvicinalo al coordinatore o a un ripetitore, poi riprova.", "Move it closer to the coordinator or a repeater, then try again."),
                 t("Se resta irraggiungibile, rimuovilo e ripeti l'accoppiamento.", "If it stays unreachable, remove it and pair it again.")]))
    elif rec["silent"]:
        hours = int((now - rec["seen"]) / 3600)
        out.append(_finding("silent", rec, "medium",
            t("Dispositivo che non comunica più", "Device no longer reporting"),
            t("{name} è a batteria e non invia dati da {h} ore.", "{name} is battery powered and has not reported for {h} hours.")
            .format(name=name, h=hours),
            [t("Sostituisci o ricarica la batteria: è la causa più frequente.", "Replace or recharge the battery: it is the most common cause."),
             t("Premi il pulsante del dispositivo per forzare un invio e verifica che torni a comunicare.",
               "Press the device's button to force a report and check that it starts reporting again.")]))
    if rec["battery_low"] and not rec["offline"]:
        level = rec["battery"]
        out.append(_finding("battery", rec, "medium" if level is not None and level <= 5 else "low",
            t("Batteria in esaurimento", "Battery running low"),
            (t("{name}: batteria al {p}%.", "{name}: battery at {p}%.").format(name=name, p=int(level)) if level is not None
             else t("{name} segnala la batteria scarica.", "{name} reports a low battery.").format(name=name)),
            [t("Sostituisci o ricarica la batteria prima che il dispositivo smetta di funzionare.",
               "Replace or recharge the battery before the device stops working.")]))
    if rec["weak"] and not rec["offline"]:
        signal = f"LQI {int(rec['lqi'])}" if rec["lqi"] is not None else f"{int(rec['rssi'])} dBm"
        out.append(_finding("weak", rec, "low",
            t("Segnale debole", "Weak signal"),
            t("{name} comunica con un segnale molto basso ({s}): può perdere comandi o scollegarsi.",
              "{name} is communicating with a very low signal ({s}): it may miss commands or drop off.").format(name=name, s=signal),
            [t("Avvicina il dispositivo o aggiungi un ripetitore (un dispositivo alimentato a rete) lungo il percorso.",
               "Move the device closer or add a repeater (a mains-powered device) along the path."),
             t("Tieni il coordinatore lontano da porte USB 3 e router Wi-Fi, che disturbano il segnale.",
               "Keep the coordinator away from USB 3 ports and Wi-Fi routers, which interfere with the signal.")]))
    if rec["update"]:
        out.append(_finding("update", rec, "low",
            t("Aggiornamento firmware disponibile", "Firmware update available"),
            t("Per {name} è disponibile un aggiornamento: spesso corregge anche problemi di sicurezza.",
              "An update is available for {name}: it often fixes security issues too.").format(name=name),
            [t("Apri il dispositivo in Home Assistant e installa l'aggiornamento.",
               "Open the device in Home Assistant and install the update.")]))
    if rec["permit_join"]:
        out.append(_finding("permit_join", rec, "medium",
            t("Accoppiamento Zigbee lasciato aperto", "Zigbee pairing left open"),
            t("La rete accetta nuovi dispositivi: chiunque sia a portata radio può aggiungerne uno.",
              "The network is accepting new devices: anyone within radio range can add one."),
            [t("Disattiva 'Permit join' in Zigbee2MQTT appena finito di aggiungere dispositivi.",
               "Turn off 'Permit join' in Zigbee2MQTT as soon as you have finished adding devices.")]))
    return out


def _incident(kind: str, severity: str, title: str, detail: str, network: str, rec: dict | None, now: int) -> dict:
    ref = rec["id"] if rec else "network"
    return {
        "id": f"{kind}:{network}:{ref}:{now}", "ts": now, "type": kind, "severity": severity, "title": title,
        "detail": detail, "device_key": None, "ip": None, "device": rec["name"] if rec else None,
        "ha_device": rec["id"] if rec else None, "network": network, "acknowledged": False,
    }


def update(data: dict, registry: dict, options: dict, now: int) -> tuple[list[dict], list[dict]]:
    """Aggiorna lo stato delle reti; restituisce i problemi attuali e gli incidenti appena accaduti."""
    store = data.setdefault("smarthome", {"devices": {}, "baseline_done": False})
    old = store["devices"]
    baseline_done = store.get("baseline_done", False)
    enabled = enabled_networks(options)
    # Una sezione appena attivata (o spostata dall'opzione su Zigbee2MQTT) parte da zero:
    # i suoi dispositivi non sono "nuovi", sono solo visti per la prima volta.
    watched = set(store.get("enabled", list(NETWORKS))) if store.get("mode") == bool(options.get("zigbee2mqtt_in_zigbee", True)) else set()
    current: dict[str, dict] = {}
    registry_ids = {d["id"] for d in registry.get("devs", [])}
    for device in registry.get("devs", []):
        if is_ours(device) or not (device.get("h") or {}).get("n"):
            continue
        network = classify(device, bool(options.get("zigbee2mqtt_in_zigbee", True)))
        if network in enabled:
            rec = _record(device, network, options, now)
            rec["first_seen"] = (old.get(rec["id"]) or {}).get("first_seen", now)
            current[rec["id"]] = rec

    findings = [f for rec in current.values() for f in _findings(rec, now)]
    incidents: list[dict] = []
    if baseline_done:
        for network in (n for n in enabled if n in watched):
            label = NETWORKS[network]
            recs = [r for r in current.values() if r["network"] == network]
            net = str(label)
            went_offline = [r for r in recs if r["offline"] and r["id"] in old and not old[r["id"]].get("offline")]
            # Tanti dispositivi che cadono insieme sono un solo guasto (coordinatore, bridge, alimentazione).
            if len(went_offline) >= 3 and len(went_offline) * 2 >= len(recs):
                incidents.append(_incident("network_outage", "high",
                    t("Rete {net}: gran parte dei dispositivi non risponde", "{net} network: most devices are not responding").format(net=net),
                    t("{n} dispositivi su {tot} hanno smesso di rispondere nello stesso momento: controlla coordinatore o bridge.",
                      "{n} devices out of {tot} stopped responding at the same time: check the coordinator or bridge.")
                    .format(n=len(went_offline), tot=len(recs)), network, None, now))
            else:
                for rec in went_offline:
                    incidents.append(_incident("device_offline", "medium",
                        t("{net}: un dispositivo ha smesso di rispondere", "{net}: a device stopped responding").format(net=net),
                        t("{name} era raggiungibile al controllo precedente e ora non lo è più.",
                          "{name} was reachable at the previous check and no longer is.").format(name=rec["name"]), network, rec, now))
            for rec in recs:
                before = old.get(rec["id"])
                if before is None:
                    incidents.append(_incident("new_device", "medium",
                        t("Nuovo dispositivo nella rete {net}", "New device on the {net} network").format(net=net),
                        t("{name}{model} è comparso in Home Assistant. Se non l'hai aggiunto tu, controlla chi ha accesso all'accoppiamento.",
                          "{name}{model} appeared in Home Assistant. If you did not add it, check who has access to pairing.")
                        .format(name=rec["name"], model=f" ({rec['model']})" if rec["model"] else ""), network, rec, now))
                elif (before.get("battery") is not None and rec["battery"] is not None
                      and before["battery"] - rec["battery"] >= BATTERY_DROP):
                    incidents.append(_incident("battery_drop", "low",
                        t("{net}: calo improvviso della batteria", "{net}: sudden battery drop").format(net=net),
                        t("La batteria di {name} è passata dal {a}% al {b}% dall'ultimo controllo.",
                          "The battery of {name} went from {a}% to {b}% since the last check.")
                        .format(name=rec["name"], a=int(before["battery"]), b=int(rec["battery"])), network, rec, now))
            # "Rimosso" solo se è sparito da Home Assistant, non se ha cambiato sezione.
            for gone in (o for o in old.values() if o["network"] == network and o["id"] not in registry_ids):
                incidents.append(_incident("device_removed", "low",
                    t("Dispositivo rimosso dalla rete {net}", "Device removed from the {net} network").format(net=net),
                    t("{name} non è più presente in Home Assistant.", "{name} is no longer present in Home Assistant.")
                    .format(name=gone["name"]), network, gone, now))
    store.update(devices=current, baseline_done=True, read_at=now, enabled=enabled,
                 mode=bool(options.get("zigbee2mqtt_in_zigbee", True)))
    return findings, incidents[:MAX_INCIDENTS_PER_CHECK]


def view(data: dict) -> dict:
    """Stato delle reti per pannello e sensori: riepilogo e dispositivi di ogni rete."""
    store = data.get("smarthome") or {}
    devices = list((store.get("devices") or {}).values())
    open_by_net: dict[str, int] = {}
    for f in data["findings"].values():
        if f["status"] == "open" and f.get("network"):
            open_by_net[f["network"]] = open_by_net.get(f["network"], 0) + 1
    networks = []
    for key in store.get("enabled", list(NETWORKS)):
        label = NETWORKS[key]
        recs = sorted((d for d in devices if d["network"] == key), key=lambda d: d["name"].lower())
        networks.append({
            "key": key, "label": str(label), "devices": recs,
            "summary": {
                "total": len(recs),
                "unreachable": sum(1 for d in recs if d["offline"]),
                "silent": sum(1 for d in recs if d["silent"]),
                "low_battery": sum(1 for d in recs if d["battery_low"]),
                "weak_signal": sum(1 for d in recs if d["weak"]),
                "updates": sum(1 for d in recs if d["update"]),
                "battery_powered": sum(1 for d in recs if d["battery"] is not None),
                "open_findings": open_by_net.get(key, 0),
            },
        })
    return {"read_at": store.get("read_at"), "networks": networks}
