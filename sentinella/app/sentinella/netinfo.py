"""Individua la rete locale da controllare e il gateway."""

import ipaddress
import json
import logging
import socket
import subprocess

log = logging.getLogger(__name__)

# Interfacce che non appartengono alla LAN di casa (container, VPN, loopback).
SKIP_IFACES = ("lo", "docker", "veth", "hassio", "br-", "tun", "tap", "wg", "tailscale", "zt")

# Reti più grandi di così vengono ridotte al /24 dell'host: una scansione
# di migliaia di indirizzi su una rete domestica è quasi sempre un errore.
MIN_PREFIX = 22


def _run_json(cmd):
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout
        return json.loads(out)
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def _clamp(ip: str, prefix: int) -> ipaddress.IPv4Network:
    if prefix < MIN_PREFIX:
        log.warning("Rete /%s troppo ampia: limito la scansione al /24 di %s", prefix, ip)
        prefix = 24
    return ipaddress.ip_network(f"{ip}/{prefix}", strict=False)


def local_ip() -> str | None:
    """Indirizzo dell'host sull'interfaccia usata per uscire (nessun pacchetto inviato)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def gateway() -> str | None:
    routes = _run_json(["ip", "-j", "-4", "route", "show", "default"])
    if routes:
        for route in routes:
            if route.get("gateway"):
                return route["gateway"]
    return None


def detect_networks() -> list[ipaddress.IPv4Network]:
    """Reti delle interfacce fisiche; in mancanza di `ip`, il /24 dell'host."""
    nets: list[ipaddress.IPv4Network] = []
    routes = _run_json(["ip", "-j", "-4", "route", "show", "default"]) or []
    default_devs = {r.get("dev") for r in routes if r.get("dev")}
    for iface in _run_json(["ip", "-j", "-4", "addr", "show"]) or []:
        name = iface.get("ifname", "")
        if name.startswith(SKIP_IFACES):
            continue
        if default_devs and name not in default_devs:
            continue
        for addr in iface.get("addr_info", []):
            if addr.get("family") == "inet" and addr.get("local"):
                net = _clamp(addr["local"], int(addr.get("prefixlen", 24)))
                if net not in nets:
                    nets.append(net)
    if not nets:
        ip = local_ip()
        if ip and not ip.startswith("127."):
            nets.append(_clamp(ip, 24))
    return nets


def resolve_networks(configured: list[str]) -> list[ipaddress.IPv4Network]:
    nets = []
    for item in configured or []:
        try:
            net = ipaddress.ip_network(str(item).strip(), strict=False)
        except ValueError:
            log.warning("Rete non valida nelle opzioni, ignorata: %r", item)
            continue
        if net.version == 4:
            nets.append(net)
    return nets or detect_networks()
