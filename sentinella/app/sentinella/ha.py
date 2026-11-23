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
_manual: dict | None = None

TOKEN_VAR = "SUPERVISOR_TOKEN"
# s6-overlay (init dell'immagine base) non passa l'ambiente del container al processo:
# lo conserva in questi file, da cui va riletto.
S6_ENV_DIRS = ("/run/s6/container_environment", "/var/run/s6/container_environment")
_token_cache: list[str] = []


def _token() -> str | None:
    if _token_cache:
        return _token_cache[0]
    value = os.environ.get(TOKEN_VAR)
    for folder in S6_ENV_DIRS:
        if value:
            break
        try:
            with open(os.path.join(folder, TOKEN_VAR), encoding="utf-8") as handle:
                value = handle.read().strip()
        except OSError:
            continue
    if value:
        _token_cache.append(value)
    return value or None

# Esito dell'ultimo invio, mostrato nel pannello per capire dove finiscono i sensori.
status = {"channel": "nessuno", "detail": "fuori da Home Assistant: nessun sensore pubblicato",
          "entities": 0, "last_ok": None, "error": None, "mqtt_reason": None}


def configure(options: dict) -> None:
    """Broker indicato a mano nelle opzioni: ha la precedenza su quello offerto dal Supervisor."""
    global _manual
    host = str(options.get("mqtt_host") or "").strip()
    _manual = {
        "host": host, "port": int(options.get("mqtt_port") or 1883),
        "username": options.get("mqtt_username") or None,
        "password": options.get("mqtt_password") or None, "ssl": False,
    } if host else None


def _request(url: str, payload=None, method=None):
    token = _token()
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
    if _manual:
        return _manual
    now = time.time()
    # Senza broker si riprova spesso: Mosquitto può essere installato o avviato dopo Sentinella.
    if now - _mqtt_cache["at"] > (600 if _mqtt_cache["settings"] else 60):
        reply = _request(f"{SUPERVISOR}/services/mqtt")
        settings = (reply or {}).get("data") or None
        if settings and not settings.get("host"):
            settings = None
        _mqtt_cache.update(at=now, settings=settings)
        status["mqtt_reason"] = None if settings else (
            "il Supervisor non mette a disposizione un broker MQTT: l'add-on Mosquitto non è installato o "
            "non è avviato. Per un broker diverso compila le opzioni mqtt_host, mqtt_username e mqtt_password")
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
                reason = {4: "utente o password errati", 5: "utente non autorizzato"}.get(connack[3], f"codice {connack[3]}")
                raise OSError(f"connessione rifiutata dal broker ({reason})")
            for topic, payload in messages:
                data = _mstr(topic) + payload.encode()
                sock.sendall(b"\x31" + _varlen(len(data)) + data)  # PUBLISH, QoS 0, retain
            # Il PINGRESP arriva dopo che il broker ha elaborato tutto ciò che precede.
            sock.sendall(b"\xc0\x00")
            _recv_exact(sock, 2)
            sock.sendall(b"\xe0\x00")
        return True
    except OSError as exc:
        where = f"{settings.get('host')}:{settings.get('port') or 1883}"
        status["mqtt_reason"] = f"broker {where} non utilizzabile: {exc}"
        log.warning("Pubblicazione MQTT non riuscita (%s): %s", where, exc)
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


def _rest_publish(entity: dict) -> bool:
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
    return _request(f"{API}/states/{_rest_entity_id(entity)}", {"state": state, "attributes": attrs}) is not None


# ---------------------------------------------------------------- interfaccia usata dal motore

def channel() -> str:
    if _manual:
        return "mqtt"
    if not _token():
        return "nessuno"
    return "mqtt" if mqtt_settings() else "api"


def _report(channel_name: str, detail: str, count: int, error: str | None) -> None:
    changed = (status["channel"], status["error"]) != (channel_name, error)
    status.update(channel=channel_name, detail=detail, entities=count, error=error)
    if not error:
        status["last_ok"] = int(time.time())
    if changed:
        (log.warning if error else log.info)(
            "Sensori verso Home Assistant: canale %s, %s, %d entità%s",
            channel_name, detail, count, f" - ERRORE: {error}" if error else "")


def publish(entities: list[dict]) -> None:
    has_token = bool(_token())
    if not has_token and not _manual:
        return _report("nessuno", "token del Supervisor non trovato", 0,
                       "l'add-on non riesce a leggere SUPERVISOR_TOKEN: nessun sensore viene pubblicato")
    settings = mqtt_settings()
    if settings:
        messages = [m for e in entities for m in _mqtt_messages(e)]
        if mqtt_publish(settings, messages):
            status["mqtt_reason"] = None
            where = f"{settings['host']}:{settings.get('port') or 1883}"
            origin = "indicato nelle opzioni" if _manual else "fornito dal Supervisor"
            return _report("mqtt", f"broker {where} ({origin})", len(entities), None)
    if not has_token:
        return _report("nessuno", "broker MQTT non raggiungibile", 0, status["mqtt_reason"])
    sent = sum(1 for entity in entities if _rest_publish(entity))
    _report("api", "API di Home Assistant (nessun broker MQTT utilizzabile)", sent,
            None if sent == len(entities) else f"Home Assistant ha accettato {sent} entità su {len(entities)}")


def remove(domain: str, entity_id: str) -> None:
    """Elimina un'entità (dispositivo dimenticato dall'utente)."""
    if not _token():
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
