"""Collega i dispositivi trovati in rete a ciò che Home Assistant conosce già.

Il registro dei dispositivi non è esposto dall'API REST: lo si legge facendo
valutare a Home Assistant un template che lo restituisce in JSON. Le
corrispondenze si cercano per MAC (connessioni e identificativi del
dispositivo) e per IP (indirizzo di configurazione, attributi e stato delle
entità).
"""

import logging
import re
from urllib.parse import urlparse

from . import ha

log = logging.getLogger(__name__)

MAX_ENTITIES = 15
IP_RE = r"^\d{1,3}(\.\d{1,3}){3}$"

# {integrations} viene sostituito: le versioni di Home Assistant senza config_entry_attr usano la variante vuota.
TEMPLATE = r"""
{%- set ns = namespace(devs=[], ents=[]) -%}
{%- for did in states | map(attribute='entity_id') | map('device_id') | reject('none') | unique -%}
  {%- set d = namespace(ents=[], doms=[]) -%}
  {%- for eid in device_entities(did) -%}
    {%- if state_attr(eid, 'sorgente') != 'sentinella' -%}{%- set d.ents = d.ents + [eid] -%}{%- endif -%}
  {%- endfor -%}
  __INTEGRATIONS__
  {%- set ns.devs = ns.devs + [{
    'id': did,
    'name': (device_attr(did, 'name_by_user') or device_attr(did, 'name') or '') | string,
    'manufacturer': (device_attr(did, 'manufacturer') or '') | string,
    'model': (device_attr(did, 'model') or '') | string,
    'sw': (device_attr(did, 'sw_version') or '') | string,
    'url': (device_attr(did, 'configuration_url') or '') | string,
    'area': (area_name(did) or '') | string,
    'connections': (device_attr(did, 'connections') or []) | list,
    'identifiers': (device_attr(did, 'identifiers') or []) | list,
    'entities': d.ents,
    'integrations': d.doms | unique | list
  }] -%}
{%- endfor -%}
{%- for s in states -%}
  {%- set a = s.attributes -%}
  {%- set mac = a.get('mac') or a.get('mac_address') -%}
  {%- set ip = a.get('ip') or a.get('ip_address') or a.get('host') -%}
  {%- set st = s.state if s.state is match('__IP_RE__') else '' -%}
  {%- if (mac or ip or st) and a.get('sorgente') != 'sentinella' -%}
    {%- set ns.ents = ns.ents + [{
      'entity_id': s.entity_id, 'name': s.name | string, 'mac': (mac or '') | string,
      'ip': (ip or '') | string, 'state_ip': st, 'device': (device_id(s.entity_id) or '') | string
    }] -%}
  {%- endif -%}
{%- endfor -%}
{{ {'devs': ns.devs, 'ents': ns.ents} | tojson }}
""".replace("__IP_RE__", IP_RE.replace("\\", "\\\\"))

INTEGRATIONS = """{%- for ce in device_attr(did, 'config_entries') or [] -%}
    {%- set d.doms = d.doms + [config_entry_attr(ce, 'domain') | string] -%}
  {%- endfor -%}"""

status = {"ok": None, "devices": 0, "error": None}


def fetch() -> dict | None:
    """Registro di Home Assistant in forma compatta; None se non è leggibile."""
    if not ha._token():
        status.update(ok=None, error="fuori da Home Assistant")
        return None
    for integrations in (INTEGRATIONS, ""):
        reply = ha._request(f"{ha.API}/template", {"template": TEMPLATE.replace("__INTEGRATIONS__", integrations)})
        if isinstance(reply, dict) and "devs" in reply:
            status.update(ok=True, devices=len(reply["devs"]), error=None)
            return reply
    status.update(ok=False, error="Home Assistant non ha restituito il registro dei dispositivi (vedi il log)")
    log.warning("Registro dei dispositivi di Home Assistant non leggibile: collegamenti non aggiornati")
    return None


def _hex(value) -> str:
    return re.sub(r"[^0-9a-f]", "", str(value).lower())


def _url_host(url: str) -> str | None:
    try:
        return urlparse(url).hostname
    except ValueError:
        return None


def _is_ours(device: dict) -> bool:
    """Dispositivo creato solo da Sentinella (via MQTT): non è un collegamento alla domotica."""
    idents = [str(i[-1]) if isinstance(i, (list, tuple)) and i else str(i) for i in device.get("identifiers", [])]
    return bool(idents) and all(i.startswith("sentinella") for i in idents) and not device.get("entities")


def match(dev: dict, registry: dict) -> dict:
    """Dispositivi ed entità di Home Assistant che corrispondono a un dispositivo di rete."""
    mac, ip = _hex(dev.get("mac") or ""), dev.get("ip")
    by_id = {d["id"]: d for d in registry.get("devs", [])}
    hits: dict[str, set] = {}
    loose = []  # entità senza dispositivo (device_tracker, ping, ...)

    for device in registry.get("devs", []):
        reasons = set()
        if mac and len(mac) == 12:
            if any(_hex(c[-1]) == mac for c in device.get("connections", []) if c):
                reasons.add("MAC")
            if any(mac in _hex(i[-1]) for i in device.get("identifiers", []) if i and len(_hex(i[-1])) >= 12):
                reasons.add("MAC")
        if ip and _url_host(device.get("url") or "") == ip:
            reasons.add("indirizzo di configurazione")
        if reasons:
            hits.setdefault(device["id"], set()).update(reasons)

    for entity in registry.get("ents", []):
        reason = None
        if mac and len(mac) == 12 and _hex(entity.get("mac")) == mac:
            reason = "MAC nell'entità"
        elif ip and ip in (entity.get("ip"), entity.get("state_ip")):
            reason = "IP nell'entità"
        if not reason:
            continue
        if entity.get("device") in by_id:
            hits.setdefault(entity["device"], set()).add(reason)
        else:
            loose.append({"entity_id": entity["entity_id"], "name": entity.get("name") or "", "match": reason})

    devices = []
    for did, reasons in hits.items():
        device = by_id[did]
        if _is_ours(device):
            continue
        devices.append({
            "id": did, "name": device.get("name") or "", "manufacturer": device.get("manufacturer") or "",
            "model": device.get("model") or "", "sw": device.get("sw") or "", "area": device.get("area") or "",
            "integrations": [i for i in device.get("integrations", []) if i and i != "None"],
            "entities": device.get("entities", [])[:MAX_ENTITIES],
            "entity_count": len(device.get("entities", [])),
            "match": sorted(reasons),
        })
    devices = [d for d in devices if d["entity_count"] or d["integrations"] not in ([], ["mqtt"])]
    return {"linked": bool(devices or loose), "devices": devices, "entities": loose[:MAX_ENTITIES]}
