"""Legge da Home Assistant ciò che conosce già: dispositivi, entità e il loro stato di salute.

Il registro dei dispositivi non è esposto dall'API REST: lo si legge facendo
valutare a Home Assistant un template che lo restituisce in JSON, a pagine per
non superare i limiti di dimensione. Serve a due cose: collegare i dispositivi
della rete locale alla domotica (per MAC o per IP) e analizzare le altre reti
(Zigbee, Z-Wave, Matter, Bluetooth, MQTT) senza interrogarle direttamente.
"""

import logging
import re
from urllib.parse import urlparse

from . import ha
from .i18n import t

log = logging.getLogger(__name__)

MAX_ENTITIES = 15
PAGE = 120
MAX_PAGES = 40
IP_RE = r"^\d{1,3}(\.\d{1,3}){3}$"

# Per ogni dispositivo si riassume la salute direttamente nel template ("h"):
# n entità, un = non disponibili, bat = batteria minima, lqi/rssi = segnale,
# seen = ultima comunicazione, upd = aggiornamento disponibile, zw = stato del nodo Z-Wave,
# pj = accoppiamento Zigbee aperto. __INTEGRATIONS__ ha una variante vuota per le versioni
# di Home Assistant senza config_entry_attr.
TEMPLATE = r"""
{%- set ns = namespace(devs=[], ents=[]) -%}
{%- set ids = states | map(attribute='entity_id') | map('device_id') | reject('none') | unique | list -%}
{%- for did in ids[start:start + count] -%}
  {%- set d = namespace(ents=[], doms=[], n=0, un=0, bat=none, batlow=false, lqi=none, rssi=none, seen=0, upd=false, zw=none, pj=false) -%}
  {%- for s in expand(device_entities(did)) -%}
    {%- set a = s.attributes -%}
    {%- if a.get('managed_by') != 'sentinella' -%}
      {%- set d.ents = d.ents + [s.entity_id] -%}
      {%- set d.n = d.n + 1 -%}
      {%- set dc = a.get('device_class') -%}
      {%- set unit = a.get('unit_of_measurement') -%}
      {%- if s.state == 'unavailable' -%}
        {%- set d.un = d.un + 1 -%}
      {%- else -%}
        {%- if s.state != 'unknown' -%}
          {%- set ts = as_timestamp(s.last_reported | default(s.last_updated), 0) | int(0) -%}
          {%- if ts > d.seen -%}{%- set d.seen = ts -%}{%- endif -%}
        {%- endif -%}
        {%- if s.domain == 'sensor' and dc == 'battery' and s.state | float(-1) >= 0 -%}
          {%- if d.bat is none or s.state | float(0) < d.bat -%}{%- set d.bat = s.state | float(0) -%}{%- endif -%}
        {%- elif s.domain == 'binary_sensor' and dc == 'battery' and s.state == 'on' -%}
          {%- set d.batlow = true -%}
        {%- elif s.domain == 'sensor' and unit == 'lqi' and s.state | float(-1) >= 0 -%}
          {%- set d.lqi = s.state | float(0) -%}
        {%- elif s.domain == 'sensor' and dc == 'signal_strength' and unit == 'dBm' and s.state | float(1) < 0 -%}
          {%- set d.rssi = s.state | float(0) -%}
        {%- elif s.domain == 'update' and s.state == 'on' -%}
          {%- set d.upd = true -%}
        {%- elif s.domain == 'sensor' and s.entity_id.endswith('_node_status') -%}
          {%- set d.zw = s.state | string -%}
        {%- elif s.domain == 'switch' and s.entity_id.endswith('permit_join') and s.state == 'on' -%}
          {%- set d.pj = true -%}
        {%- endif -%}
      {%- endif -%}
    {%- endif -%}
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
    'entities': d.ents[:__MAX_ENTITIES__],
    'integrations': d.doms | unique | list,
    'h': {'n': d.n, 'un': d.un, 'bat': d.bat, 'batlow': d.batlow, 'lqi': d.lqi, 'rssi': d.rssi,
          'seen': d.seen, 'upd': d.upd, 'zw': d.zw, 'pj': d.pj}
  }] -%}
{%- endfor -%}
{%- if start == 0 -%}
{%- for s in states -%}
  {%- set a = s.attributes -%}
  {%- set mac = a.get('mac') or a.get('mac_address') -%}
  {%- set ip = a.get('ip') or a.get('ip_address') or a.get('host') -%}
  {%- set st = s.state if s.state is match('__IP_RE__') else '' -%}
  {%- if (mac or ip or st) and a.get('managed_by') != 'sentinella' -%}
    {%- set ns.ents = ns.ents + [{
      'entity_id': s.entity_id, 'name': s.name | string, 'mac': (mac or '') | string,
      'ip': (ip or '') | string, 'state_ip': st, 'device': (device_id(s.entity_id) or '') | string
    }] -%}
  {%- endif -%}
{%- endfor -%}
{%- endif -%}
{{ {'devs': ns.devs, 'ents': ns.ents, 'total': ids | length} | tojson }}
""".replace("__IP_RE__", IP_RE.replace("\\", "\\\\")).replace("__MAX_ENTITIES__", str(MAX_ENTITIES + 5))

INTEGRATIONS = """{%- for ce in device_attr(did, 'config_entries') or [] -%}
    {%- set d.doms = d.doms + [config_entry_attr(ce, 'domain') | string] -%}
  {%- endfor -%}"""

status = {"ok": None, "devices": 0, "error": None}


def _page(integrations: str, start: int) -> dict | None:
    reply = ha._request(f"{ha.API}/template", {
        "template": TEMPLATE.replace("__INTEGRATIONS__", integrations),
        "variables": {"start": start, "count": PAGE},
    })
    return reply if isinstance(reply, dict) and "devs" in reply else None


def fetch() -> dict | None:
    """Registro di Home Assistant in forma compatta; None se non è leggibile."""
    if not ha._token():
        status.update(ok=None, error=t("fuori da Home Assistant", "not running inside Home Assistant"))
        return None
    for integrations in (INTEGRATIONS, ""):
        first = _page(integrations, 0)
        if first is None:
            continue
        registry = {"devs": list(first["devs"]), "ents": first.get("ents", [])}
        total = int(first.get("total") or 0)
        for page in range(1, MAX_PAGES):
            if page * PAGE >= total:
                break
            more = _page(integrations, page * PAGE)
            if more is None:
                break
            registry["devs"].extend(more["devs"])
        status.update(ok=True, devices=len(registry["devs"]), error=None)
        return registry
    status.update(ok=False, error=t("Home Assistant non ha restituito il registro dei dispositivi (vedi il log)",
                                    "Home Assistant did not return the device registry (see the log)"))
    log.warning("Home Assistant device registry not readable: links and smart home checks not updated")
    return None


def _hex(value) -> str:
    return re.sub(r"[^0-9a-f]", "", str(value).lower())


def _url_host(url: str) -> str | None:
    try:
        return urlparse(url).hostname
    except ValueError:
        return None


def is_ours(device: dict) -> bool:
    """Dispositivo creato solo da Sentinella (via MQTT): non fa parte della domotica dell'utente."""
    idents = [str(i[-1]) if isinstance(i, (list, tuple)) and i else str(i) for i in device.get("identifiers", [])]
    return bool(idents) and all(i.startswith("sentinella") for i in idents)


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
            reasons.add(t("indirizzo di configurazione", "configuration URL"))
        if reasons:
            hits.setdefault(device["id"], set()).update(reasons)

    for entity in registry.get("ents", []):
        reason = None
        if mac and len(mac) == 12 and _hex(entity.get("mac")) == mac:
            reason = t("MAC nell'entità", "MAC in the entity")
        elif ip and ip in (entity.get("ip"), entity.get("state_ip")):
            reason = t("IP nell'entità", "IP in the entity")
        if not reason:
            continue
        if entity.get("device") in by_id:
            hits.setdefault(entity["device"], set()).add(reason)
        else:
            loose.append({"entity_id": entity["entity_id"], "name": entity.get("name") or "", "match": reason})

    devices = []
    for did, reasons in hits.items():
        device = by_id[did]
        count = int((device.get("h") or {}).get("n") or len(device.get("entities", [])))
        if is_ours(device) or not count:
            continue
        devices.append({
            "id": did, "name": device.get("name") or "", "manufacturer": device.get("manufacturer") or "",
            "model": device.get("model") or "", "sw": device.get("sw") or "", "area": device.get("area") or "",
            "integrations": [i for i in device.get("integrations", []) if i and i != "None"],
            "entities": device.get("entities", [])[:MAX_ENTITIES], "entity_count": count,
            "match": sorted(reasons),
        })
    return {"linked": bool(devices or loose), "devices": devices, "entities": loose[:MAX_ENTITIES]}
