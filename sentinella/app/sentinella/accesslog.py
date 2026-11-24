"""Accessi a Home Assistant: tentativi falliti e indirizzi bloccati, letti dal log.

Home Assistant scrive nel proprio log ogni richiesta con credenziali non valide
e ogni indirizzo che blocca. Il log si legge tramite il Supervisor; gli accessi
riusciti non vi compaiono, quindi non si possono segnalare.
"""

import hashlib
import ipaddress
import logging
import re

from . import ha
from .i18n import t

log = logging.getLogger(__name__)

NETWORK = "access"
LOG_LINES = 2000
WINDOW = 24 * 3600
KEEP = 7 * 86400
MAX_ATTEMPTS = 600
BRUTE_FORCE = 5

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
TS_RE = re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")
LOGIN_RE = re.compile(
    r"Login attempt or request with invalid authentication from (?P<host>\S+) \((?P<ip>[0-9a-fA-F:.]+)\)"
    r"(?:\.\s*Requested URL: '(?P<url>[^']*)')?(?:\.\s*\((?P<agent>.*)\))?")
BAN_RE = re.compile(r"Banned IP (?P<ip>[0-9a-fA-F:.]+) for too many login attempts")

status = {"ok": None, "error": None}


def fetch() -> str | None:
    """Ultime righe del log di Home Assistant; None se il Supervisor non le concede."""
    for headers in ({"Range": f"entries=:-{LOG_LINES}:", "Accept": "text/plain"}, {"Accept": "text/plain"}):
        text = ha.supervisor_text("/core/logs", headers)
        if text is not None:
            status.update(ok=True, error=None)
            return text
    status.update(ok=False, error=t(
        "il log di Home Assistant non è leggibile: controlla che l'add-on abbia il permesso di accesso al Supervisor",
        "the Home Assistant log cannot be read: check that the add-on has permission to access the Supervisor"))
    return None


def is_external(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local)


def parse(text: str) -> tuple[list[dict], list[dict]]:
    """Tentativi falliti e blocchi presenti nel testo del log."""
    attempts, bans = [], []
    for raw in text.splitlines():
        line = ANSI_RE.sub("", raw)
        login, ban = LOGIN_RE.search(line), BAN_RE.search(line)
        if not login and not ban:
            continue
        stamp = TS_RE.search(line)
        entry = {"id": hashlib.sha1(line.encode("utf-8", "replace")).hexdigest()[:16],
                 "when": stamp.group(1) if stamp else ""}
        if login:
            attempts.append({**entry, "ip": login["ip"], "host": login["host"],
                             "url": (login["url"] or "")[:120], "agent": (login["agent"] or "")[:120]})
        else:
            bans.append({**entry, "ip": ban["ip"]})
    return attempts, bans


def _incident(kind: str, severity: str, title: str, detail: str, ip: str, device: dict | None, now: int) -> dict:
    return {
        "id": f"{kind}:{NETWORK}:{ip}:{now}", "ts": now, "type": kind, "severity": severity, "title": title,
        "detail": detail, "device_key": device["key"] if device else None, "ip": ip,
        "device": (device.get("name") or device.get("hostname") or ip) if device else ip,
        "network": NETWORK, "acknowledged": False,
    }


def _finding(fid: str, severity: str, title: str, detail: str, steps: list[str]) -> dict:
    return {"id": f"access:{fid}", "severity": severity, "title": title, "detail": detail, "remediation": steps,
            "category": NETWORK, "network": NETWORK, "scope": NETWORK, "port": None, "action": None,
            "device_key": None, "ip": None, "ha_device": {"id": "", "name": "Home Assistant"}}


def update(data: dict, text: str, now: int) -> tuple[list[dict], list[dict]]:
    """Registra i nuovi tentativi; restituisce i problemi attuali e gli incidenti appena accaduti."""
    store = data.setdefault("access", {"attempts": [], "bans": [], "seen": []})
    seen = set(store.get("seen", []))
    attempts, bans = parse(text)
    new_attempts = [a for a in attempts if a["id"] not in seen]
    new_bans = [b for b in bans if b["id"] not in seen]
    # L'orario scritto nel log è quello locale di Home Assistant: per le finestre di tempo si usa
    # il momento in cui la riga è stata vista, che non dipende dal fuso orario.
    for item in new_attempts + new_bans:
        item["seen_at"] = now
    store["attempts"] = [a for a in store.get("attempts", []) + new_attempts if now - a["seen_at"] < KEEP][-MAX_ATTEMPTS:]
    store["bans"] = [b for b in store.get("bans", []) + new_bans if now - b["seen_at"] < KEEP][-100:]
    store["seen"] = (store.get("seen", []) + [x["id"] for x in new_attempts + new_bans])[-4000:]
    store["read_at"] = now

    by_ip = {d["ip"]: d for d in data["devices"].values() if d.get("ip")}
    incidents = []
    grouped: dict[str, list[dict]] = {}
    for attempt in new_attempts:
        grouped.setdefault(attempt["ip"], []).append(attempt)
    for ip, items in grouped.items():
        external = is_external(ip)
        last = items[-1]
        origin = t("da Internet", "from the Internet") if external else t("dalla rete locale", "from the local network")
        detail = (t("Una richiesta con credenziali non valide da {ip} ({origin}) alle {when}.",
                    "One request with invalid credentials from {ip} ({origin}) at {when}.") if len(items) == 1 else
                  t("{n} richieste con credenziali non valide da {ip} ({origin}), l'ultima alle {when}.",
                    "{n} requests with invalid credentials from {ip} ({origin}), the latest at {when}.")).format(
                       n=len(items), ip=ip, origin=origin, when=last["when"] or "?")
        if last["url"]:
            detail += " " + t("Indirizzo richiesto: {u}.", "Requested URL: {u}.").format(u=last["url"])
        if last["agent"]:
            detail += " " + t("Client: {a}.", "Client: {a}.").format(a=last["agent"])
        incidents.append(_incident(
            "failed_login", "high" if external or len(items) >= BRUTE_FORCE else "medium",
            t("Tentativi di accesso falliti a Home Assistant", "Failed login attempts to Home Assistant"),
            detail, ip, by_ip.get(ip), now))
    for ban in new_bans:
        incidents.append(_incident(
            "ip_banned", "high", t("Home Assistant ha bloccato un indirizzo", "Home Assistant banned an address"),
            t("{ip} è stato bloccato per troppi tentativi di accesso falliti ({when}).",
              "{ip} was banned after too many failed login attempts ({when}).").format(ip=ban["ip"], when=ban["when"] or "?"),
            ban["ip"], by_ip.get(ban["ip"]), now))

    findings = []
    recent = [a for a in store["attempts"] if now - a["seen_at"] < WINDOW]
    if recent:
        external = [a for a in recent if is_external(a["ip"])]
        sources = len({a["ip"] for a in recent})
        findings.append(_finding(
            "failed_logins", "high" if len(external) >= 10 else "medium" if external else "low",
            t("Tentativi di accesso falliti nelle ultime 24 ore", "Failed login attempts in the last 24 hours"),
            t("{n} tentativi da {s} indirizzi, di cui {e} da Internet.",
              "{n} attempts from {s} addresses, {e} of them from the Internet.").format(
                  n=len(recent), s=sources, e=len(external)),
            [t("Se gli indirizzi sono tuoi (un telefono con la password vecchia, un'app, un'integrazione), aggiorna le credenziali su quel dispositivo.",
               "If the addresses are yours (a phone with an old password, an app, an integration), update the credentials on that device."),
             t("Attiva l'autenticazione a più fattori per ogni utente: Profilo > Sicurezza.",
               "Enable multi-factor authentication for every user: Profile > Security."),
             t("Attiva il blocco automatico in configuration.yaml: http: ip_ban_enabled: true, login_attempts_threshold: 5.",
               "Enable automatic banning in configuration.yaml: http: ip_ban_enabled: true, login_attempts_threshold: 5."),
             t("Non esporre la porta 8123 direttamente su Internet: usa una VPN o Home Assistant Cloud.",
               "Do not expose port 8123 directly to the Internet: use a VPN or Home Assistant Cloud.")]))
    external_url = str((ha.core_config() or {}).get("external_url") or "")
    if external_url.lower().startswith("http://"):
        findings.append(_finding(
            "external_http", "high",
            t("Accesso esterno a Home Assistant senza HTTPS", "External access to Home Assistant without HTTPS"),
            t("L'URL esterno configurato ({u}) usa HTTP: password e token viaggiano in chiaro su Internet.",
              "The configured external URL ({u}) uses HTTP: passwords and tokens travel in clear text over the Internet.")
            .format(u=external_url[:80]),
            [t("Usa un accesso cifrato: Home Assistant Cloud, una VPN, oppure un reverse proxy con certificato.",
               "Use encrypted access: Home Assistant Cloud, a VPN, or a reverse proxy with a certificate."),
             t("Poi aggiorna l'URL esterno in Impostazioni > Sistema > Rete.",
               "Then update the external URL in Settings > System > Network.")]))
    return findings, incidents


def view(data: dict, now: int) -> dict:
    """Riepilogo per pannello e sensori: tentativi delle ultime 24 ore raggruppati per indirizzo."""
    store = data.get("access") or {}
    recent = [a for a in store.get("attempts", []) if now - a["seen_at"] < WINDOW]
    banned = sorted({b["ip"] for b in store.get("bans", [])})
    names = {d["ip"]: d.get("name") or d.get("hostname") or "" for d in data["devices"].values() if d.get("ip")}
    sources: dict[str, dict] = {}
    for a in recent:
        src = sources.setdefault(a["ip"], {
            "ip": a["ip"], "host": a["host"], "external": is_external(a["ip"]), "count": 0, "device": names.get(a["ip"], ""),
            "banned": a["ip"] in banned, "urls": [], "agents": []})
        src["count"] += 1
        src["last"], src["last_seen"] = a["when"], a["seen_at"]
        for key, value in (("urls", a["url"]), ("agents", a["agent"])):
            if value and value not in src[key] and len(src[key]) < 5:
                src[key].append(value)
    ordered = sorted(sources.values(), key=lambda s: (-s["count"], s["ip"]))
    return {
        "read_at": store.get("read_at"), "ok": status["ok"], "error": status["error"],
        "attempts_24h": len(recent), "external_24h": sum(1 for a in recent if is_external(a["ip"])),
        "sources": ordered, "banned": banned,
    }
