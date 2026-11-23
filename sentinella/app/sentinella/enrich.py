"""Identificazione dei dispositivi: cosa sono, oltre a un indirizzo.

Le fonti sempre attive sono annunci che i dispositivi fanno comunque in rete
(mDNS, SSDP, NetBIOS): una richiesta standard, nessun tentativo di accesso.
La scansione approfondita (versioni dei servizi e sistema operativo con nmap)
è più lenta e più rumorosa, quindi va abilitata nelle opzioni.
"""

import logging
import re
import shutil
import socket
import struct
import subprocess
import time
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

from . import netinfo, upnp
from .i18n import L

log = logging.getLogger(__name__)

MDNS_ADDR = ("224.0.0.251", 5353)
MDNS_META = "_services._dns-sd._udp.local"
# Tipi chiesti comunque: non tutti i dispositivi rispondono all'elenco generale dei servizi.
MDNS_COMMON = [
    "_googlecast._tcp", "_airplay._tcp", "_raop._tcp", "_hap._tcp", "_homekit._tcp", "_ipp._tcp",
    "_ipps._tcp", "_printer._tcp", "_pdl-datastream._tcp", "_scanner._tcp", "_smb._tcp",
    "_afpovertcp._tcp", "_ssh._tcp", "_workstation._tcp", "_http._tcp", "_esphomelib._tcp",
    "_shelly._tcp", "_spotify-connect._tcp", "_sonos._tcp", "_companion-link._tcp",
    "_apple-mobdev2._tcp", "_device-info._tcp", "_home-assistant._tcp", "_matter._tcp",
    "_androidtvremote2._tcp", "_amzn-wplay._tcp", "_miio._udp", "_hue._tcp", "_rtsp._tcp",
]
MAX_TEXT = 80


def _clean(value, limit: int = MAX_TEXT) -> str:
    text = "".join(c if c.isprintable() else " " for c in str(value or ""))
    return " ".join(text.split())[:limit]


# ---------------------------------------------------------------- mDNS

def _dns_name(name: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode() for p in name.strip(".").split(".")) + b"\x00"


def _mdns_query(names: list[str]) -> bytes:
    # Classe 0x8001: bit "risposta unicast", così la risposta arriva alla nostra porta e non serve la 5353.
    header = struct.pack(">HHHHHH", 0, 0, len(names), 0, 0, 0)
    return header + b"".join(_dns_name(n) + struct.pack(">HH", 12, 0x8001) for n in names)


def _read_name(data: bytes, off: int) -> tuple[str, int]:
    labels, end, jumps = [], None, 0
    while True:
        length = data[off]
        if length == 0:
            off += 1
            break
        if length & 0xC0 == 0xC0:
            if end is None:
                end = off + 2
            off = ((length & 0x3F) << 8) | data[off + 1]
            jumps += 1
            if jumps > 20:
                raise ValueError("puntatori DNS in ciclo")
            continue
        labels.append(data[off + 1:off + 1 + length].decode("utf-8", "replace"))
        off += 1 + length
    return ".".join(labels), (end if end is not None else off)


def parse_dns(data: bytes) -> list[tuple]:
    """Record PTR e TXT di un pacchetto DNS; pacchetti malformati sollevano ValueError/IndexError."""
    _, _, questions, answers, authority, additional = struct.unpack(">HHHHHH", data[:12])
    off = 12
    for _ in range(questions):
        _, off = _read_name(data, off)
        off += 4
    records = []
    for _ in range(answers + authority + additional):
        name, off = _read_name(data, off)
        rtype, _, _, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        if rtype == 12:
            records.append(("PTR", name, _read_name(data, off)[0]))
        elif rtype == 16:
            txt, pos = {}, off
            while pos < off + rdlen:
                size = data[pos]
                item = data[pos + 1:pos + 1 + size].decode("utf-8", "replace")
                pos += 1 + size
                if "=" in item:
                    key, value = item.split("=", 1)
                    txt[key.lower()] = value
            records.append(("TXT", name, txt))
        off += rdlen
    return records


def _strip_local(name: str) -> str:
    return name[:-6] if name.endswith(".local") else name


def digest_mdns(packets: list[tuple[str, bytes]]) -> tuple[dict, set]:
    """Raggruppa i record per indirizzo che ha risposto; restituisce anche i tipi di servizio scoperti."""
    found: dict[str, dict] = {}
    types: set[str] = set()
    for ip, data in packets:
        try:
            records = parse_dns(data)
        except (ValueError, IndexError, struct.error):
            continue
        entry = found.setdefault(ip, {"services": [], "names": [], "txt": {}})
        for kind, name, value in records:
            if kind == "PTR" and name == MDNS_META:
                types.add(_strip_local(value))
            elif kind == "PTR" and name.startswith("_"):
                service = _strip_local(name)
                if service not in entry["services"]:
                    entry["services"].append(service)
                instance = value[:-len(name) - 1] if value.endswith("." + name) else value
                instance = _clean(instance)
                if instance and instance not in entry["names"]:
                    entry["names"].append(instance)
            elif kind == "TXT":
                for key, text in value.items():
                    entry["txt"].setdefault(key, _clean(text))
    return {ip: e for ip, e in found.items() if e["services"] or e["txt"]}, types


def mdns(wait: float = 2.5) -> dict[str, dict]:
    packets: list[tuple[str, bytes]] = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        local = netinfo.local_ip()
        if local:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local))

        def collect(seconds: float) -> None:
            deadline = time.time() + seconds
            while True:
                left = deadline - time.time()
                if left <= 0:
                    return
                sock.settimeout(left)
                try:
                    data, addr = sock.recvfrom(9000)
                except OSError:
                    return
                packets.append((addr[0], data))

        sock.sendto(_mdns_query([MDNS_META]), MDNS_ADDR)
        collect(wait)
        _, types = digest_mdns(packets)
        wanted = sorted(set(MDNS_COMMON) | {t for t in types if re.fullmatch(r"[\w.-]{3,60}", t)})
        for start in range(0, len(wanted), 15):
            sock.sendto(_mdns_query([t + ".local" for t in wanted[start:start + 15]]), MDNS_ADDR)
        collect(wait)
    except OSError as exc:
        log.info("mDNS not available: %s", exc)
    finally:
        sock.close()
    return digest_mdns(packets)[0]


# ---------------------------------------------------------------- SSDP / UPnP

def _ssdp_description(url: str) -> dict:
    try:
        with urllib.request.urlopen(url, timeout=4) as resp:
            root = ET.fromstring(resp.read(500_000))
    except (OSError, ET.ParseError, ValueError):
        return {}
    wanted = {"friendlyName": "friendly_name", "manufacturer": "manufacturer", "modelName": "model",
              "modelNumber": "model_number", "deviceType": "device_type"}
    info = {}
    for el in root.iter():
        key = wanted.get(upnp._local(el.tag))
        if key and key not in info and el.text and el.text.strip():
            info[key] = _clean(el.text)
    return info


def ssdp(wait: float = 3.0) -> dict[str, dict]:
    locations: dict[str, list[str]] = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(wait)
    try:
        sock.sendto(b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\n'
                    b"MX: 2\r\nST: ssdp:all\r\n\r\n", upnp.SSDP_ADDR)
        deadline = time.time() + wait
        while time.time() < deadline:
            data, addr = sock.recvfrom(4096)
            match = re.search(rb"^location:\s*(\S+)", data, re.I | re.M)
            if not match:
                continue
            url = match.group(1).decode("latin-1")
            parsed = urlparse(url)
            # Si scarica la descrizione solo dall'host che ha risposto, in rete privata.
            if parsed.scheme == "http" and parsed.hostname == addr[0] and upnp._is_private(addr[0]):
                urls = locations.setdefault(addr[0], [])
                if url not in urls and len(urls) < 3:
                    urls.append(url)
    except OSError:
        pass
    finally:
        sock.close()

    def describe(item):
        ip, urls = item
        for url in urls:
            info = _ssdp_description(url)
            if info.get("friendly_name") or info.get("model"):
                return ip, info
        return ip, {}

    with ThreadPoolExecutor(max_workers=16) as pool:
        return {ip: info for ip, info in pool.map(describe, locations.items()) if info}


# ---------------------------------------------------------------- NetBIOS

NBSTAT_QUERY = (b"\x53\x4e\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20" + b"CK" + b"A" * 30
                + b"\x00\x00\x21\x00\x01")


def parse_nbstat(data: bytes) -> dict:
    count = data[56]
    info = {}
    for i in range(count):
        entry = data[57 + i * 18:75 + i * 18]
        if len(entry) < 18:
            break
        name, suffix = _clean(entry[:15].decode("latin-1")), entry[15]
        group = bool(entry[16] & 0x80)
        if suffix == 0x00 and name:
            info.setdefault("workgroup" if group else "netbios", name)
    return info


def netbios(ips: list[str], wait: float = 2.0) -> dict[str, dict]:
    found: dict[str, dict] = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for ip in ips:
            try:
                sock.sendto(NBSTAT_QUERY, (ip, 137))
            except OSError:
                continue
        deadline = time.time() + wait
        while True:
            left = deadline - time.time()
            if left <= 0:
                break
            sock.settimeout(left)
            try:
                data, addr = sock.recvfrom(2048)
            except ConnectionResetError:
                continue  # Windows segnala così un host che rifiuta la porta: non è la fine dell'ascolto
            try:
                info = parse_nbstat(data)
            except IndexError:
                continue
            if info:
                found[addr[0]] = info
    except OSError:
        pass
    finally:
        sock.close()
    return found


# ---------------------------------------------------------------- scansione approfondita (nmap)

def parse_nmap_deep(xml_text: str) -> dict:
    root = ET.fromstring(xml_text)
    out = {"ports": {}, "os": None}
    for port in root.iter("port"):
        service = port.find("service")
        state = port.find("state")
        if service is None or state is None or state.get("state") != "open":
            continue
        product = " ".join(filter(None, [service.get("product"), service.get("version")]))
        if product:
            out["ports"][int(port.get("portid"))] = _clean(product)
    best = max(root.iter("osmatch"), key=lambda m: int(m.get("accuracy") or 0), default=None)
    if best is not None and int(best.get("accuracy") or 0) >= 85:
        out["os"] = _clean(best.get("name"))
        out["os_accuracy"] = int(best.get("accuracy"))
    return out


def _deep_one(item) -> tuple[str, dict]:
    ip, ports = item
    cmd = ["nmap", "-Pn", "-sV", "--version-light", "-O", "--osscan-limit", "--host-timeout", "90s",
           "-p", ",".join(str(p) for p in ports), "-oX", "-", ip]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=120).stdout
        return ip, parse_nmap_deep(out)
    except (OSError, ET.ParseError, ValueError, subprocess.SubprocessError) as exc:
        log.info("Deep scan of %s failed: %s", ip, exc)
        return ip, {}


def deep_scan(open_ports: dict[str, list[int]]) -> dict[str, dict]:
    if not shutil.which("nmap"):
        log.warning("Deep scan requested but nmap is not available")
        return {}
    targets = [(ip, ports) for ip, ports in open_ports.items() if ports]
    with ThreadPoolExecutor(max_workers=6) as pool:
        return {ip: info for ip, info in pool.map(_deep_one, targets) if info}


# ---------------------------------------------------------------- raccolta e sintesi

def collect(ips: list[str]) -> dict[str, dict]:
    """Interroga le fonti in parallelo; restituisce per ogni indirizzo i dati grezzi trovati."""
    with ThreadPoolExecutor(max_workers=3) as pool:
        jobs = {"mdns": pool.submit(mdns), "ssdp": pool.submit(ssdp), "netbios": pool.submit(netbios, ips)}
        results = {}
        for name, job in jobs.items():
            try:
                results[name] = job.result()
            except Exception:  # una fonte che fallisce non deve togliere le altre
                log.exception("Source %s failed", name)
                results[name] = {}
    wanted = set(ips)
    out: dict[str, dict] = {}
    for name, per_ip in results.items():
        for ip, info in per_ip.items():
            if ip in wanted:
                out.setdefault(ip, {})[name] = info
    log.info("Identification: mDNS %d, SSDP %d, NetBIOS %d devices",
             *(len(results[n]) for n in ("mdns", "ssdp", "netbios")))
    return out


def is_private_mac(mac: str | None) -> bool:
    """MAC casuale ("privato"): il secondo carattere è 2, 6, A o E."""
    return bool(mac) and len(mac) > 1 and mac[1].lower() in "26ae"


TYPES = {
    "router": L("Router", "Router"), "computer": L("Computer", "Computer"),
    "telefono": L("Telefono o tablet", "Phone or tablet"), "tv": L("TV o streaming", "TV or streaming"),
    "audio": L("Audio", "Audio"), "stampante": L("Stampante", "Printer"),
    "telecamera": L("Telecamera o DVR", "Camera or DVR"), "nas": L("NAS", "NAS"),
    "iot": L("Dispositivo smart", "Smart device"), "hub": L("Hub domotico", "Smart home hub"),
    "console": L("Console", "Game console"), "server": L("Server", "Server"),
    "sconosciuto": L("Non identificato", "Unidentified"),
}
IOT_VENDORS = ("espressif", "shelly", "allterco", "tuya", "sonoff", "itead", "xiaomi", "tp-link", "meross",
               "broadlink", "philips lighting", "signify", "ikea", "switchbot", "nanoleaf", "aqara", "lumi")
CAMERA_VENDORS = ("hikvision", "dahua", "reolink", "ezviz", "foscam", "amcrest", "axis comm", "imou", "tapo")
TV_VENDORS = ("lg electronics", "samsung", "sony", "tcl", "hisense", "roku", "vizio", "panasonic", "amazon")
NAS_VENDORS = ("synology", "qnap", "asustor", "western digital", "netgear")
CONSOLE_VENDORS = ("nintendo", "sony interactive", "microsoft")
PRINTER_VENDORS = ("hewlett", "hp inc", "canon", "epson", "brother", "lexmark", "kyocera", "xerox", "ricoh")


def classify(dev: dict, raw: dict) -> str:
    services = set((raw.get("mdns") or {}).get("services", []))
    ssdp_type = ((raw.get("ssdp") or {}).get("device_type") or "").lower()
    ports = {p["port"] for p in dev.get("ports", [])}
    vendor = (dev.get("vendor") or "").lower() + " " + ((raw.get("ssdp") or {}).get("manufacturer") or "").lower()
    name = " ".join(filter(None, [dev.get("hostname"), dev.get("name")])).lower()

    def has(*names):
        return any(n in services for n in names)

    def by(vendors):
        return any(v in vendor for v in vendors)

    if dev.get("is_gateway") or "internetgatewaydevice" in ssdp_type:
        return "router"
    if has("_ipp._tcp", "_ipps._tcp", "_printer._tcp", "_pdl-datastream._tcp", "_scanner._tcp") or 9100 in ports \
            or (by(PRINTER_VENDORS) and (631 in ports or 515 in ports)):
        return "stampante"
    if ports & {554, 37777, 34567} or by(CAMERA_VENDORS) or has("_rtsp._tcp"):
        return "telecamera"
    if has("_googlecast._tcp", "_androidtvremote2._tcp", "_amzn-wplay._tcp") or "mediarenderer" in ssdp_type \
            or "tv" in ssdp_type or (has("_airplay._tcp") and "tv" in name):
        return "audio" if any(w in name for w in ("speaker", "nest-audio", "home-mini", "sonos")) else "tv"
    if has("_sonos._tcp", "_spotify-connect._tcp", "_raop._tcp") and not has("_companion-link._tcp"):
        return "audio"
    if has("_home-assistant._tcp", "_hue._tcp") or 8123 in ports:
        return "hub"
    if has("_esphomelib._tcp", "_shelly._tcp", "_hap._tcp", "_homekit._tcp", "_miio._udp", "_matter._tcp") \
            or by(IOT_VENDORS):
        return "iot"
    if by(NAS_VENDORS) and ports & {445, 5000, 5001, 2049} or has("_afpovertcp._tcp") and 5000 in ports:
        return "nas"
    if by(CONSOLE_VENDORS) and not ports & {3389, 445}:
        return "console"
    if by(TV_VENDORS) and ports & {8008, 8009, 9000, 8080, 7676} and not ports & {22, 445}:
        return "tv"
    if has("_apple-mobdev2._tcp") or (is_private_mac(dev.get("mac")) and not ports):
        return "telefono"
    if ports & {3389, 445, 139, 548} or has("_workstation._tcp", "_smb._tcp", "_companion-link._tcp") \
            or (raw.get("netbios") or {}).get("netbios"):
        return "computer"
    if ports & {22, 80, 443, 3306, 5432, 2375, 8006}:
        return "server" if ports & {3306, 5432, 2375, 8006, 22} else "sconosciuto"
    return "sconosciuto"


def describe(dev: dict, raw: dict, deep: dict | None = None) -> dict:
    """Scheda sintetica del dispositivo a partire dai dati grezzi delle varie fonti."""
    m, s, n = raw.get("mdns") or {}, raw.get("ssdp") or {}, raw.get("netbios") or {}
    txt = m.get("txt", {})
    model = s.get("model") or txt.get("md") or txt.get("model") or txt.get("ty") or txt.get("am") or txt.get("product")
    if s.get("model_number") and model and s["model_number"] not in model:
        model = f"{model} {s['model_number']}"
    friendly = txt.get("fn") or s.get("friendly_name") or (m.get("names") or [None])[0] or n.get("netbios")
    kind = classify(dev, raw)
    sources = [label for label, data in (("mDNS", m), ("SSDP", s), ("NetBIOS", n), ("nmap", deep)) if data]
    info = {
        "type": kind, "type_label": str(TYPES[kind]),
        "friendly_name": _clean(friendly) or None, "model": _clean(model) or None,
        "manufacturer": _clean(s.get("manufacturer")) or None,
        "netbios": n.get("netbios"), "workgroup": n.get("workgroup"),
        "services": m.get("services", [])[:20],
        "firmware": _clean(txt.get("fv") or txt.get("version") or txt.get("fw") or txt.get("sw"), 40) or None,
        "os": (deep or {}).get("os"), "os_accuracy": (deep or {}).get("os_accuracy"),
        "private_mac": is_private_mac(dev.get("mac")),
        "sources": sources,
    }
    return {k: v for k, v in info.items() if v not in (None, [], "")}
