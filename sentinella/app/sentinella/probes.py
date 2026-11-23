"""Verifiche attive sui servizi trovati.

Sono tutte non distruttive: una sola connessione, nessun tentativo di
indovinare password, nessuna scrittura. Servono a distinguere "la porta è
aperta" da "il servizio accetta chiunque".
"""

import http.client
import re
import socket
import ssl
import struct

TIMEOUT = 3
HTTP_PORTS = {80, 81, 3000, 5000, 8000, 8080, 8081, 8123, 8888, 9000, 9090, 9200, 2375}
HTTPS_PORTS = {443, 5001, 8006, 8443, 10000}
TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)


def _text(raw: bytes, limit: int = 120) -> str:
    """Testo stampabile e corto: i banner arrivano da dispositivi non fidati."""
    cleaned = "".join(c if c.isprintable() else " " for c in raw.decode("latin-1", "replace"))
    return " ".join(cleaned.split())[:limit]


def _recv(sock: socket.socket, size: int) -> bytes:
    try:
        return sock.recv(size)
    except OSError:
        return b""


def http_info(ip: str, port: int) -> dict:
    tls = port in HTTPS_PORTS
    try:
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(ip, port, timeout=TIMEOUT, context=ctx)
        else:
            conn = http.client.HTTPConnection(ip, port, timeout=TIMEOUT)
        conn.request("GET", "/", headers={"User-Agent": "Sentinella", "Accept": "*/*"})
        resp = conn.getresponse()
        body = resp.read(8192)
        conn.close()
    except (OSError, http.client.HTTPException):
        return {}
    info = {"tls": tls, "status": resp.status}
    if resp.getheader("Server"):
        info["server"] = _text(resp.getheader("Server").encode("latin-1", "replace"), 80)
    auth = resp.getheader("WWW-Authenticate")
    if auth:
        info["auth"] = _text(auth.split()[0].encode("latin-1", "replace"), 20).lower()
    title = TITLE_RE.search(body)
    if title:
        info["title"] = _text(title.group(1), 80)
    if port == 9200 and resp.status == 200 and b"cluster_name" in body:
        info["open_elasticsearch"] = True
    return info


def banner(ip: str, port: int) -> dict:
    try:
        with socket.create_connection((ip, port), TIMEOUT) as s:
            s.settimeout(2)
            data = _recv(s, 200)
    except OSError:
        return {}
    return {"banner": _text(data)} if data else {}


def ftp_anonymous(ip: str, port: int) -> dict:
    info = {}
    try:
        with socket.create_connection((ip, port), TIMEOUT) as s:
            s.settimeout(TIMEOUT)
            greeting = _recv(s, 300)
            if greeting:
                info["banner"] = _text(greeting)
            s.sendall(b"USER anonymous\r\n")
            reply = _recv(s, 300)
            if reply.startswith(b"331"):
                s.sendall(b"PASS sentinella@localhost\r\n")
                reply = _recv(s, 300)
            info["anonymous"] = reply.startswith(b"230")
            s.sendall(b"QUIT\r\n")
    except OSError:
        pass
    return info


def mqtt_anonymous(ip: str, port: int) -> dict:
    client_id = b"sentinella-check"
    variable = b"\x00\x04MQTT\x04\x02\x00\x0a" + struct.pack(">H", len(client_id)) + client_id
    packet = b"\x10" + bytes([len(variable)]) + variable
    try:
        with socket.create_connection((ip, port), TIMEOUT) as s:
            s.settimeout(TIMEOUT)
            s.sendall(packet)
            reply = _recv(s, 4)
            if len(reply) == 4 and reply[0] == 0x20:
                s.sendall(b"\xe0\x00")  # DISCONNECT
                return {"anonymous": reply[3] == 0}
    except OSError:
        pass
    return {}


def redis_noauth(ip: str, port: int) -> dict:
    try:
        with socket.create_connection((ip, port), TIMEOUT) as s:
            s.settimeout(TIMEOUT)
            s.sendall(b"PING\r\n")
            reply = _recv(s, 64)
    except OSError:
        return {}
    if reply.startswith(b"+PONG"):
        return {"noauth": True}
    if reply.startswith(b"-NOAUTH") or b"DENIED" in reply:
        return {"noauth": False}
    return {}


def docker_api(ip: str, port: int) -> dict:
    try:
        conn = http.client.HTTPConnection(ip, port, timeout=TIMEOUT)
        conn.request("GET", "/version")
        resp = conn.getresponse()
        body = resp.read(4096)
        conn.close()
    except (OSError, http.client.HTTPException):
        return {}
    return {"docker_api": resp.status == 200 and b"ApiVersion" in body}


def vnc_auth(ip: str, port: int) -> dict:
    """Legge i tipi di autenticazione offerti: il tipo 1 significa 'nessuna password'."""
    try:
        with socket.create_connection((ip, port), TIMEOUT) as s:
            s.settimeout(TIMEOUT)
            version = _recv(s, 12)
            if not version.startswith(b"RFB "):
                return {}
            info = {"banner": _text(version)}
            s.sendall(version)
            if version[4:11] in (b"003.003", b"003.005"):
                raw = _recv(s, 4)
                types = [struct.unpack(">I", raw)[0]] if len(raw) == 4 else []
            else:
                count = _recv(s, 1)
                types = list(_recv(s, count[0])) if count and count[0] else []
            if types:
                info["noauth"] = 1 in types
            return info
    except OSError:
        return {}


def smb_v1(ip: str, port: int) -> dict:
    """Propone il solo dialetto SMBv1: se il server lo accetta, il protocollo obsoleto è attivo."""
    dialect = b"\x02NT LM 0.12\x00"
    header = (
        b"\xffSMB\x72" + b"\x00" * 4 + b"\x18" + b"\x01\x28" + b"\x00" * 12
        + b"\x00\x00" + b"\x2f\x4b" + b"\x00\x00" + b"\xc5\x5e"
    )
    body = header + b"\x00" + struct.pack("<H", len(dialect)) + dialect
    packet = struct.pack(">I", len(body)) + body
    try:
        with socket.create_connection((ip, port), TIMEOUT) as s:
            s.settimeout(TIMEOUT)
            s.sendall(packet)
            reply = _recv(s, 64)
    except OSError:
        return {}
    if len(reply) >= 13 and reply[4:8] == b"\xffSMB":
        return {"smbv1": reply[9:13] == b"\x00" * 4}
    return {"smbv1": False}


SPECIFIC = {
    21: ftp_anonymous, 1883: mqtt_anonymous, 6379: redis_noauth, 2375: docker_api,
    5900: vnc_auth, 5901: vnc_auth, 445: smb_v1,
}
BANNER_PORTS = {22, 23, 2323, 25}


def probe(ip: str, port: int, active: bool = True) -> dict:
    info: dict = {}
    try:
        if port in HTTP_PORTS or port in HTTPS_PORTS:
            info.update(http_info(ip, port))
        if port in BANNER_PORTS:
            info.update(banner(ip, port))
        if active and port in SPECIFIC:
            info.update(SPECIFIC[port](ip, port))
    except Exception:  # un dispositivo che risponde in modo anomalo non deve fermare la scansione
        pass
    return info
