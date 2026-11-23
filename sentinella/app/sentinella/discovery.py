"""Scoperta dei dispositivi accesi sulla rete.

Con nmap (presente nell'add-on) si usa l'ARP scan, che restituisce anche MAC
e produttore. Senza nmap si ripiega su ping + tabella ARP del sistema.
"""

import logging
import platform
import re
import shutil
import socket
import subprocess
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor

log = logging.getLogger(__name__)

MAC_RE = re.compile(r"([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})")
IP_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")


def _norm_mac(mac: str) -> str:
    return mac.replace("-", ":").lower()


def _nmap(cidr: str) -> list[dict] | None:
    if not shutil.which("nmap"):
        return None
    try:
        out = subprocess.run(
            ["nmap", "-sn", "-oX", "-", "--host-timeout", "30s", cidr],
            capture_output=True, text=True, timeout=600,
        ).stdout
        root = ET.fromstring(out)
    except (OSError, ET.ParseError, subprocess.SubprocessError) as exc:
        log.warning("nmap non riuscito (%s): uso il metodo di riserva", exc)
        return None
    hosts = []
    for host in root.iter("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        entry = {"ip": None, "mac": None, "vendor": None, "hostname": None}
        for addr in host.iter("address"):
            if addr.get("addrtype") == "ipv4":
                entry["ip"] = addr.get("addr")
            elif addr.get("addrtype") == "mac":
                entry["mac"] = _norm_mac(addr.get("addr", ""))
                entry["vendor"] = addr.get("vendor")
        name = host.find("hostnames/hostname")
        if name is not None:
            entry["hostname"] = name.get("name")
        if entry["ip"]:
            hosts.append(entry)
    return hosts


def _ping(ip: str) -> bool:
    if platform.system() == "Windows":
        cmd = ["ping", "-n", "1", "-w", "800", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return False
    # Su Windows il codice di uscita è 0 anche per "host di destinazione non raggiungibile".
    return res.returncode == 0 and "ttl=" in res.stdout.lower()


def _arp_table() -> dict[str, str]:
    table: dict[str, str] = {}
    for cmd in (["ip", "neigh"], ["arp", "-a"]):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        for line in out.splitlines():
            ip, mac = IP_RE.search(line), MAC_RE.search(line)
            if ip and mac:
                mac_n = _norm_mac(mac.group(1))
                if mac_n not in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                    table[ip.group(1)] = mac_n
        if table:
            break
    return table


def _rdns(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return None


def _fallback(net) -> list[dict]:
    ips = [str(h) for h in net.hosts()] or [str(net.network_address)]
    with ThreadPoolExecutor(max_workers=64) as pool:
        alive = [ip for ip, up in zip(ips, pool.map(_ping, ips)) if up]
        arp = _arp_table()
        # Chi non risponde al ping ma compare nella tabella ARP è comunque acceso.
        for ip in arp:
            if ip in ips and ip not in alive:
                alive.append(ip)
        names = list(pool.map(_rdns, alive))
    return [
        {"ip": ip, "mac": arp.get(ip), "vendor": None, "hostname": name}
        for ip, name in zip(alive, names)
    ]


def discover(net) -> list[dict]:
    hosts = _nmap(str(net))
    if hosts is None:
        hosts = _fallback(net)
    return hosts
