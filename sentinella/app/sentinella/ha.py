"""Canali verso Home Assistant.

Le entità vengono pubblicate via MQTT discovery quando il Supervisor mette a
disposizione un broker (add-on Mosquitto): sono entità vere, con ID univoco e
stato conservato dal broker. Senza broker si usa l'API degli stati di Home
Assistant: stessi sensori, ma spariscono al riavvio di HA finché non vengono
ripubblicati (lo si fa periodicamente).
"""

import json
import logging
import os
import socket
import ssl
import struct
import time
import urllib.error
import urllib.request

from . import __version__

log = logging.getLogger(__name__)

SUPERVISOR = os.environ.get("SENTINELLA_SUPERVISOR", "http://supervisor")
API = f"{SUPERVISOR}/core/api"
DISCOVERY_PREFIX = "homeassistant"
STATE_PREFIX = "sentinella"
MAIN_DEVICE = {
    "identifiers": ["sentinella"], "name": "Sentinella", "manufacturer": "Sentinella",
    "model": "Controllo di sicurezza della rete", "sw_version": __version__,
}

_mqtt_cache = {"at": 0.0, "settings": None}


def _request(url: str, payload=None, method=None):
    token = os.environ.get("SUPERVISOR_TOKEN")
    if not token:
        return None
    req = urllib.request.Request(
        url, data=None if payload is None else json.dumps(payload).encode(), method=method,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read()
        return json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            log.warning("Home Assistant ha risposto %s a %s", exc.code, url)
    except (OSError, ValueError) as exc:
        log.warning("Home Assistant non raggiungibile (%s): %s", url, exc)
    return None


# ---------------------------------------------------------------- MQTT

def mqtt_settings() -> dict | None:
    """Credenziali del broker fornite dal Supervisor (None se non c'è un broker)."""
    now = time.time()
    if now - _mqtt_cache["at"] > 600:
        reply = _request(f"{SUPERVISOR}/services/mqtt")
        _mqtt_cache.update(at=now, settings=(reply or {}).get("data") or None)
    return _mqtt_cache["settings"]


def _varlen(n: int) -> bytes:
    out = bytearray()
    while True:
        digit, n = n % 128, n // 128
        out.append(digit | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _mstr(text: str) -> bytes:
    raw = text.encode()
    return struct.pack(">H", len(raw)) + raw


def _recv_exact(sock, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise OSError("connessione chiusa dal broker")
        data += chunk
    return data


def mqtt_publish(settings: dict, messages: list[tuple[str, str]]) -> bool:
    """Pubblica messaggi 'retained' con un client MQTT 3.1.1 minimale (una connessione per invio)."""
    user, password = settings.get("username"), settings.get("password")
    flags = 0x02 | (0x80 if user else 0) | (0x40 if password else 0)
    body = _mstr("MQTT") + bytes([4, flags]) + struct.pack(">H", 60) + _mstr("sentinella")
    if user:
        body += _mstr(user)
    if password:
        body += _mstr(password)
    try:
        sock = socket.create_connection((settings["host"], int(settings.get("port") or 1883)), 10)
        if settings.get("ssl"):
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=settings["host"])
        with sock:
            sock.settimeout(15)
            sock.sendall(b"\x10" + _varlen(len(body)) + body)
            connack = _recv_exact(sock, 4)
            if connack[0] != 0x20 or connack[3] != 0:
                log.warning("Il broker MQTT ha rifiutato la connessione (codice %s)", connack[3])
                return False
            for topic, payload in messages:
                data = _mstr(topic) + payload.encode()
                sock.sendall(b"\x31" + _varlen(len(data)) + data)  # PUBLISH, QoS 0, retain
            # Il PINGRESP arriva dopo che il broker ha elaborato tutto ciò che precede.
            sock.sendall(b"\xc0\x00")
            _recv_exact(sock, 2)
            sock.sendall(b"\xe0\x00")
        return True
    except OSError as exc:
        log.warning("Pubblicazione MQTT non riuscita: %s", exc)
        return False


def _mqtt_device(entity: dict) -> dict:
    dev = entity.get("device")
    if not dev:
        return MAIN_DEVICE
    info = {"identifiers": [f"sentinella_{entity['id']}"], "name": dev["name"], "via_device": "sentinella"}
    if dev.get("vendor"):
        info["manufacturer"] = dev["vendor"]
    if dev.get("mac"):
        # Con il MAC Home Assistant unisce il sensore al dispositivo già noto da altre integrazioni.
        info["connections"] = [["mac", dev["mac"]]]
    return info


def _mqtt_messages(entity: dict) -> list[tuple[str, str]]:
    topic = f"{STATE_PREFIX}/{entity['id']}"
    config = {
        "name": entity["name"], "unique_id": f"sentinella_{entity['id']}",
        "state_topic": topic, "value_template": "{{ value_json.state }}",
        "json_attributes_topic": topic, "json_attributes_template": "{{ value_json.attributes | tojson }}",
        "device": _mqtt_device(entity),
    }
    for src, dst in (("device_class", "device_class"), ("unit", "unit_of_measurement"), ("icon", "icon"),
                     ("state_class", "state_class"), ("entity_category", "entity_category")):
        if entity.get(src):
            config[dst] = entity[src]
    state = entity["state"]
    if entity["domain"] == "binary_sensor":
        state = "ON" if state else "OFF"
    return [
        (f"{DISCOVERY_PREFIX}/{entity['domain']}/sentinella/{entity['id']}/config", json.dumps(config, ensure_ascii=False)),
        (topic, json.dumps({"state": state, "attributes": entity["attributes"]}, ensure_ascii=False)),
    ]


# ---------------------------------------------------------------- API degli stati (ripiego)

def _rest_entity_id(entity: dict) -> str:
    return f"{entity['domain']}.sentinella_{entity['id']}"


def _rest_publish(entity: dict) -> None:
    state = entity["state"]
    if entity["domain"] == "binary_sensor":
        state = "on" if state else "off"
    elif state is None:
        state = "unknown"
    dev = entity.get("device")
    attrs = dict(entity["attributes"])
    attrs["friendly_name"] = f"{dev['name']} in rete" if dev else f"Sentinella {entity['name']}"
    for src, dst in (("device_class", "device_class"), ("unit", "unit_of_measurement"), ("icon", "icon"),
                     ("state_class", "state_class")):
        if entity.get(src):
            attrs[dst] = entity[src]
    _request(f"{API}/states/{_rest_entity_id(entity)}", {"state": state, "attributes": attrs})


# ---------------------------------------------------------------- interfaccia usata dal motore

def channel() -> str:
    if not os.environ.get("SUPERVISOR_TOKEN"):
        return "nessuno"
    return "mqtt" if mqtt_settings() else "api"


def publish(entities: list[dict]) -> None:
    if not os.environ.get("SUPERVISOR_TOKEN"):
        return
    settings = mqtt_settings()
    if settings:
        messages = [m for e in entities for m in _mqtt_messages(e)]
        if mqtt_publish(settings, messages):
            return
    for entity in entities:
        _rest_publish(entity)


def remove(domain: str, entity_id: str) -> None:
    """Elimina un'entità (dispositivo dimenticato dall'utente)."""
    if not os.environ.get("SUPERVISOR_TOKEN"):
        return
    settings = mqtt_settings()
    if settings:
        mqtt_publish(settings, [
            (f"{DISCOVERY_PREFIX}/{domain}/sentinella/{entity_id}/config", ""),
            (f"{STATE_PREFIX}/{entity_id}", ""),
        ])
    _request(f"{API}/states/{domain}.sentinella_{entity_id}", method="DELETE")


def fire_event(event_type: str, data: dict) -> None:
    _request(f"{API}/events/{event_type}", data)


def notify(lines: list[str]) -> None:
    if not lines:
        return
    shown = lines[:10]
    if len(lines) > 10:
        shown.append(f"... e altri {len(lines) - 10}.")
    _request(f"{API}/services/persistent_notification/create", {
        "notification_id": "sentinella",
        "title": "Sentinella: incidenti di sicurezza in rete",
        "message": "\n".join(f"- {line}" for line in shown) + "\n\nApri il pannello Sentinella per i dettagli.",
    })
