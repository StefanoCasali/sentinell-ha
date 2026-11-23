"""UPnP IGD: lettura (e rimozione) delle porte aperte verso Internet sul router.

È l'unico canale standard con cui un router dell'operatore dichiara i propri
port forwarding. Mostra solo le aperture create via UPnP: quelle inserite a
mano nel pannello del router non sono visibili da qui.
"""

import ipaddress
import logging
import re
import socket
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlparse
from xml.sax.saxutils import escape

log = logging.getLogger(__name__)

SSDP_ADDR = ("239.255.255.250", 1900)
SEARCH_TARGETS = (
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
)
WAN_SERVICES = (
    "urn:schemas-upnp-org:service:WANIPConnection:2",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
)
MAX_MAPPINGS = 256


class UpnpError(Exception):
    pass


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _is_private(host: str | None) -> bool:
    try:
        return ipaddress.ip_address(host).is_private
    except (ValueError, TypeError):
        return False


def _ssdp_locations(timeout: float = 3.0) -> list[str]:
    locations: list[str] = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(timeout)
    try:
        for target in SEARCH_TARGETS:
            msg = (
                "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
                f'MAN: "ssdp:discover"\r\nMX: 2\r\nST: {target}\r\n\r\n'
            )
            sock.sendto(msg.encode(), SSDP_ADDR)
        while True:
            data, addr = sock.recvfrom(4096)
            match = re.search(rb"^location:\s*(\S+)", data, re.I | re.M)
            if not match:
                continue
            url = match.group(1).decode("latin-1")
            host = urlparse(url).hostname
            # La descrizione deve stare sullo stesso host che ha risposto, in rete privata:
            # un annuncio SSDP non deve poterci mandare a interrogare indirizzi arbitrari.
            if host == addr[0] and _is_private(host) and url not in locations:
                locations.append(url)
    except OSError:
        pass
    finally:
        sock.close()
    return locations


def _find_service(location: str) -> dict | None:
    try:
        with urllib.request.urlopen(location, timeout=5) as resp:
            root = ET.fromstring(resp.read(1_000_000))
    except (OSError, ET.ParseError, ValueError):
        return None
    info = {"location": location, "host": urlparse(location).hostname}
    for el in root.iter():
        name = _local(el.tag)
        if name in ("friendlyName", "manufacturer", "modelName") and name not in info:
            info[name] = (el.text or "").strip()[:80]
    base = location
    for el in root.iter():
        if _local(el.tag) == "URLBase" and el.text:
            base = el.text.strip()
    services = {}
    for service in root.iter():
        if _local(service.tag) != "service":
            continue
        fields = {_local(c.tag): (c.text or "").strip() for c in service}
        if fields.get("serviceType") in WAN_SERVICES and fields.get("controlURL"):
            services[fields["serviceType"]] = fields["controlURL"]
    for service_type in WAN_SERVICES:
        if service_type in services:
            control = urljoin(base, services[service_type])
            if urlparse(control).hostname != info["host"]:
                return None
            info.update(service_type=service_type, control_url=control)
            return info
    return None


def find_gateway() -> dict | None:
    for location in _ssdp_locations():
        service = _find_service(location)
        if service:
            return service
    return None


def _soap(igd: dict, action: str, args: dict) -> dict:
    body = "".join(f"<{k}>{escape(str(v))}</{k}>" for k, v in args.items())
    envelope = (
        '<?xml version="1.0"?>'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
        f'<u:{action} xmlns:u="{igd["service_type"]}">{body}</u:{action}>'
        "</s:Body></s:Envelope>"
    )
    req = urllib.request.Request(
        igd["control_url"], data=envelope.encode(),
        headers={
            "Content-Type": 'text/xml; charset="utf-8"',
            "SOAPAction": f'"{igd["service_type"]}#{action}"',
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            raw = resp.read(200_000)
    except urllib.error.HTTPError as exc:
        detail = exc.read(4000).decode("utf-8", "replace")
        code = re.search(r"<errorCode>(\d+)</errorCode>", detail)
        raise UpnpError(code.group(1) if code else f"HTTP {exc.code}") from exc
    except OSError as exc:
        raise UpnpError(str(exc)) from exc
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise UpnpError("risposta non valida") from exc
    return {_local(el.tag): (el.text or "").strip() for el in root.iter() if len(el) == 0}


def external_ip(igd: dict) -> str | None:
    try:
        return _soap(igd, "GetExternalIPAddress", {}).get("NewExternalIPAddress") or None
    except UpnpError:
        return None


def list_mappings(igd: dict) -> list[dict]:
    mappings = []
    for index in range(MAX_MAPPINGS):
        try:
            entry = _soap(igd, "GetGenericPortMappingEntry", {"NewPortMappingIndex": index})
        except UpnpError:
            break  # 713 = indice oltre la fine dell'elenco
        if not entry.get("NewExternalPort"):
            break
        mappings.append({
            "remote_host": entry.get("NewRemoteHost", ""),
            "external_port": int(entry["NewExternalPort"]),
            "protocol": entry.get("NewProtocol", "TCP").upper(),
            "internal_port": int(entry.get("NewInternalPort") or 0),
            "internal_client": entry.get("NewInternalClient", ""),
            "enabled": entry.get("NewEnabled", "1") == "1",
            "description": entry.get("NewPortMappingDescription", "")[:80],
            "lease": int(entry.get("NewLeaseDuration") or 0),
        })
    return mappings


def delete_mapping(igd: dict, external_port: int, protocol: str, remote_host: str = "") -> None:
    _soap(igd, "DeletePortMapping", {
        "NewRemoteHost": remote_host,
        "NewExternalPort": int(external_port),
        "NewProtocol": protocol.upper(),
    })


def snapshot() -> dict:
    """Stato UPnP del router: sempre un dizionario, anche quando UPnP è spento."""
    igd = find_gateway()
    if not igd:
        return {"available": False}
    return {
        "available": True,
        "igd": igd,
        "external_ip": external_ip(igd),
        "mappings": list_mappings(igd),
    }
