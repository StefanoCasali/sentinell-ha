"""Regole: trasformano ciò che la scansione ha visto in problemi con rimedio."""

import ipaddress

SEVERITIES = ["critical", "high", "medium", "low", "info"]

# Porte per cui un'esposizione verso Internet è particolarmente grave.
RISKY_EXPOSED = {21, 22, 23, 139, 445, 1883, 2323, 2375, 3306, 3389, 5432, 5555, 5900,
                 5901, 6379, 8123, 9200, 27017, 37777, 34567}

CGNAT = ipaddress.ip_network("100.64.0.0/10")


def is_behind_nat(external_ip: str | None) -> bool:
    """Vero se l'indirizzo WAN del router è privato o del NAT dell'operatore (CGNAT)."""
    try:
        addr = ipaddress.ip_address(external_ip)
    except (ValueError, TypeError):
        return False
    return addr.is_private or addr in CGNAT

# porta -> (gravità, titolo, perché è un problema, passi per rimediare)
PORT_RULES = {
    23: ("high", "Telnet attivo",
         "Telnet trasmette utente e password in chiaro ed è il bersaglio principale dei malware per dispositivi IoT.",
         ["Entra nel pannello del dispositivo e disattiva Telnet.",
          "Se serve l'accesso remoto, usa SSH con una password robusta.",
          "Se non si può disattivare, aggiorna il firmware o sposta il dispositivo sulla rete ospiti."]),
    21: ("medium", "FTP attivo",
         "FTP trasmette credenziali e file in chiaro: chiunque sia in rete può intercettarli.",
         ["Disattiva il server FTP dal pannello del dispositivo.",
          "Per scambiare file usa SFTP o una condivisione SMB protetta da password."]),
    139: ("low", "Condivisione NetBIOS attiva",
          "Servizio di condivisione Windows datato, utile solo a dispositivi molto vecchi.",
          ["Se non hai dispositivi che lo richiedono, disattiva NetBIOS su TCP/IP nelle impostazioni di rete."]),
    445: ("low", "Condivisione file SMB attiva",
          "Normale su PC e NAS, ma ogni cartella condivisa va protetta da password.",
          ["Verifica che non ci siano cartelle condivise con 'Everyone' o accesso ospite.",
           "Disattiva la condivisione file se su questo dispositivo non la usi."]),
    3389: ("medium", "Desktop remoto (RDP) attivo",
           "RDP è tra i servizi più attaccati: basta una password debole per perdere il controllo del PC.",
           ["Se non lo usi: Impostazioni > Sistema > Desktop remoto > disattiva.",
            "Se lo usi: password robusta, autenticazione a livello di rete e mai un port forwarding diretto."]),
    5900: ("medium", "VNC attivo",
           "VNC da' il controllo completo dello schermo e spesso non cifra il traffico.",
           ["Disattiva VNC se non serve.", "Altrimenti imposta una password robusta e usalo solo via VPN."]),
    5555: ("critical", "Android Debug Bridge (ADB) aperto in rete",
           "Chiunque in rete può installare app ed eseguire comandi sul dispositivo senza password.",
           ["Sul dispositivo: Impostazioni > Opzioni sviluppatore > disattiva 'Debug ADB' / 'Debug di rete'.",
            "Su TV box economici, se l'opzione non esiste, isola il dispositivo sulla rete ospiti."]),
    1883: ("low", "Broker MQTT attivo",
           "MQTT sulla porta 1883 non è cifrato: comandi e stati della domotica viaggiano in chiaro.",
           ["Assicurati che il broker richieda utente e password.",
            "Non esporre mai questa porta verso Internet."]),
    6379: ("medium", "Redis raggiungibile in rete",
           "Redis non è pensato per essere esposto: senza password permette di leggere e scrivere tutti i dati.",
           ["Configura 'bind 127.0.0.1' oppure imposta 'requirepass' nella configurazione di Redis."]),
    2375: ("medium", "Porta dell'API Docker aperta",
           "L'API Docker senza TLS equivale a un accesso da amministratore alla macchina.",
           ["Rimuovi '-H tcp://0.0.0.0:2375' dalla configurazione del demone Docker.",
            "Se serve l'accesso remoto usa SSH oppure TLS con certificati client (porta 2376)."]),
    9200: ("medium", "Elasticsearch raggiungibile in rete",
           "Senza autenticazione chiunque in rete può leggere e cancellare gli indici.",
           ["Limita l'ascolto a localhost (network.host) oppure attiva la sicurezza integrata."]),
    27017: ("medium", "MongoDB raggiungibile in rete",
            "Le installazioni senza autenticazione espongono tutti i dati.",
            ["Imposta bindIp a 127.0.0.1 oppure attiva l'autenticazione."]),
    11211: ("medium", "Memcached raggiungibile in rete",
            "Memcached non ha autenticazione: i dati in cache sono leggibili da chiunque.",
            ["Limita l'ascolto a 127.0.0.1 (opzione -l)."]),
    3306: ("low", "MySQL/MariaDB raggiungibile in rete",
           "Un database dovrebbe ascoltare in rete solo se altri dispositivi devono davvero collegarsi.",
           ["Se lo usa solo la macchina stessa, imposta bind-address = 127.0.0.1.",
            "Verifica che non esistano utenti senza password."]),
    5432: ("low", "PostgreSQL raggiungibile in rete",
           "Un database dovrebbe ascoltare in rete solo se altri dispositivi devono davvero collegarsi.",
           ["Limita listen_addresses e pg_hba.conf agli indirizzi che ne hanno bisogno."]),
    1433: ("low", "SQL Server raggiungibile in rete",
           "Un database dovrebbe ascoltare in rete solo se altri dispositivi devono davvero collegarsi.",
           ["Se è un'istanza di sviluppo, disattiva il protocollo TCP/IP o limita il firewall alla rete locale.",
            "Verifica che l'utente 'sa' sia disattivato o abbia una password robusta."]),
    1723: ("medium", "Server VPN PPTP attivo",
           "PPTP è un protocollo VPN considerato violabile da anni.",
           ["Disattiva PPTP e passa a WireGuard o OpenVPN."]),
    37777: ("medium", "Porta di gestione DVR/telecamera aperta",
            "I videoregistratori economici hanno una lunga storia di falle e accessi di fabbrica.",
            ["Aggiorna il firmware e cambia la password di fabbrica.",
             "Disattiva l'accesso cloud/P2P se non lo usi e non aprire mai questa porta verso Internet."]),
    554: ("low", "Flusso video RTSP attivo",
          "Il video della telecamera è accessibile in rete: va protetto da password.",
          ["Verifica che il flusso RTSP richieda credenziali e che non siano quelle di fabbrica."]),
    2049: ("low", "Condivisione NFS attiva",
           "NFS si fida degli indirizzi IP: qualunque dispositivo in rete può potenzialmente montare le cartelle.",
           ["Limita le esportazioni NFS ai soli indirizzi che ne hanno bisogno."]),
    873: ("low", "Servizio rsync attivo",
          "I moduli rsync senza autenticazione permettono di leggere o sovrascrivere file.",
          ["Proteggi i moduli con 'auth users' oppure disattiva il demone rsync."]),
}
PORT_RULES[2323] = PORT_RULES[23]
PORT_RULES[5901] = PORT_RULES[5900]
PORT_RULES[34567] = PORT_RULES[37777]

# Controlli che nessuna scansione dall'interno può fare: li conferma l'utente.
ROUTER_CHECKLIST = [
    {"id": "admin_password", "title": "Password di amministrazione del router cambiata",
     "why": "La password stampata sull'etichetta o quella di fabbrica è nota a chiunque abbia avuto il router in mano.",
     "how": "Pannello del router > Gestione/Amministrazione > Account utente: imposta una password lunga e unica."},
    {"id": "wps_off", "title": "WPS disattivato",
     "why": "Il PIN WPS si forza in poche ore e consegna la password del Wi-Fi.",
     "how": "Pannello del router > Rete locale > WLAN > WPS: disattivalo su entrambe le bande."},
    {"id": "wifi_wpa", "title": "Wi-Fi in WPA2-AES o WPA3 con password robusta",
     "why": "WEP e WPA/TKIP sono violabili; una password corta si indovina con un attacco a dizionario.",
     "how": "Pannello del router > WLAN > Sicurezza: scegli WPA2-PSK (AES) o WPA2/WPA3 e una password di almeno 16 caratteri."},
    {"id": "remote_mgmt_off", "title": "Gestione remota dal lato Internet disattivata",
     "why": "Il pannello del router non deve essere raggiungibile da Internet.",
     "how": "Pannello del router > Sicurezza/Gestione > Accesso remoto (o 'Controllo servizi'): nessun servizio abilitato sul lato WAN."},
    {"id": "port_forwarding", "title": "Port forwarding manuali verificati",
     "why": "Le aperture inserite a mano non sono leggibili via UPnP: vanno controllate nel pannello.",
     "how": "Pannello del router > Internet > Sicurezza > Port forwarding (o 'Server virtuale'): elimina le regole che non riconosci."},
    {"id": "dmz_off", "title": "DMZ disattivata",
     "why": "La DMZ espone a Internet tutte le porte di un dispositivo.",
     "how": "Pannello del router > Internet > Sicurezza > DMZ: disattivata."},
    {"id": "upnp_off", "title": "UPnP disattivato (se non serve)",
     "why": "Con UPnP qualunque dispositivo o malware in rete può aprirsi porte verso Internet da solo.",
     "how": "Pannello del router > Rete locale > UPnP: disattivalo. Riattivalo solo se console o videochiamate smettono di funzionare."},
    {"id": "guest_network", "title": "Dispositivi IoT sulla rete ospiti",
     "why": "Telecamere, prese e TV economiche sono i dispositivi meno aggiornati: separarli protegge PC e telefoni.",
     "how": "Pannello del router > WLAN > Rete ospiti: attivala con isolamento dalla LAN e spostaci i dispositivi smart."},
    {"id": "firmware", "title": "Firmware del router aggiornato",
     "why": "Sui router dell'operatore gli aggiornamenti arrivano da remoto, ma solo se il router resta acceso e collegato.",
     "how": "Pannello del router > Gestione > Informazioni dispositivo: annota la versione e confrontala con quella indicata dall'assistenza dell'operatore."},
]


def _finding(fid, severity, title, detail, steps, device=None, port=None, category="servizio", action=None):
    return {
        "id": fid, "severity": severity, "title": title, "detail": detail,
        "remediation": steps, "category": category, "port": port, "action": action,
        "device_key": device["key"] if device else None,
        "ip": device["ip"] if device else None,
    }


def _bump(severity: str, to: str) -> str:
    return to if SEVERITIES.index(to) < SEVERITIES.index(severity) else severity


def device_findings(device: dict, is_new: bool) -> list[dict]:
    out = []
    key = device["key"]
    if is_new and not device.get("trusted"):
        out.append(_finding(
            f"new-device:{key}", "medium", "Nuovo dispositivo in rete",
            "Questo dispositivo non era presente nelle scansioni precedenti.",
            ["Se lo riconosci, segnalo come fidato dalla scheda Dispositivi.",
             "Se non lo riconosci, cambia la password del Wi-Fi e controlla l'elenco dei dispositivi collegati sul router."],
            device, category="dispositivo"))

    for entry in device.get("ports", []):
        port, info = entry["port"], entry.get("info", {})
        rule = PORT_RULES.get(port)
        if rule:
            severity, title, detail, steps = rule
            if port in (21,) and info.get("anonymous"):
                severity, title = "high", "FTP con accesso anonimo"
                detail = "Il server FTP accetta l'utente 'anonymous' senza password: i file sono leggibili da chiunque in rete."
            elif port == 445 and info.get("smbv1"):
                severity, title = "high", "Protocollo SMBv1 attivo"
                detail = "SMBv1 è il protocollo sfruttato da WannaCry e da molti altri malware; è obsoleto dal 2017."
                steps = ["Windows: 'Attiva o disattiva funzionalità di Windows' > togli 'Supporto per condivisione file SMB 1.0/CIFS'.",
                         "NAS: imposta SMB2 come protocollo minimo nelle impostazioni dei servizi file."]
            elif port in (5900, 5901) and info.get("noauth"):
                severity, title = "critical", "VNC senza password"
                detail = "Il server VNC accetta connessioni senza autenticazione: chiunque in rete controlla lo schermo."
            elif port == 1883 and info.get("anonymous"):
                severity, title = "high", "Broker MQTT senza autenticazione"
                detail = "Il broker accetta connessioni anonime: chiunque in rete può leggere gli stati e inviare comandi ai dispositivi."
                steps = ["Mosquitto: imposta 'allow_anonymous false' e crea gli utenti con mosquitto_passwd.",
                         "Add-on Mosquitto di Home Assistant: usa solo utenti di Home Assistant o i login definiti nell'add-on."]
            elif port == 6379 and info.get("noauth"):
                severity, title = "high", "Redis senza password"
            elif port == 2375 and info.get("docker_api"):
                severity, title = "critical", "API Docker aperta senza autenticazione"
            elif port == 9200 and info.get("open_elasticsearch"):
                severity, title = "high", "Elasticsearch senza autenticazione"
            if device.get("is_gateway") and port in (23, 2323, 21):
                severity = _bump(severity, "high")
                title += " sul router"
            out.append(_finding(f"port:{key}:{port}", severity, title, detail, steps, device, port))
        elif info.get("auth") == "basic" and not info.get("tls"):
            out.append(_finding(
                f"http-basic:{key}:{port}", "medium", "Login su HTTP non cifrato",
                "La pagina chiede utente e password senza HTTPS: le credenziali viaggiano in chiaro a ogni richiesta.",
                ["Attiva HTTPS nel pannello del dispositivo, se disponibile.",
                 "Non riutilizzare su questo dispositivo una password usata altrove."],
                device, port))
        elif device.get("is_gateway") and port == 22:
            out.append(_finding(
                f"port:{key}:22", "low", "SSH attivo sul router",
                "L'accesso SSH al router serve di rado in casa e amplia la superficie d'attacco.",
                ["Se non lo usi, disattivalo dal pannello del router (Gestione > Controllo servizi)."],
                device, port))
    return out


def router_findings(upnp: dict, devices_by_ip: dict) -> list[dict]:
    out = []
    if not upnp.get("available"):
        return out
    out.append(_finding(
        "upnp-enabled", "medium", "UPnP attivo sul router",
        "Qualunque dispositivo (o malware) nella rete può aprire porte verso Internet senza chiedere conferma.",
        ["Pannello del router > Rete locale > UPnP: disattivalo.",
         "Se console di gioco o videochiamate smettono di funzionare, riattivalo e tieni d'occhio questo elenco."],
        category="router"))

    ext = upnp.get("external_ip")
    try:
        addr = ipaddress.ip_address(ext) if ext else None
    except ValueError:
        addr = None
    behind_nat = bool(addr and (addr.is_private or addr in CGNAT))
    if behind_nat:
        out.append(_finding(
            "wan-private", "info", "Il router non ha un indirizzo pubblico",
            f"L'indirizzo WAN ({ext}) è privato: sei dietro il NAT dell'operatore (CGNAT) o un secondo router. "
            "Le porte aperte qui sotto non sono raggiungibili direttamente da Internet.",
            ["Nessun intervento necessario: è una protezione in più."], category="router"))

    for m in upnp.get("mappings", []):
        target = devices_by_ip.get(m["internal_client"])
        name = (target or {}).get("name") or (target or {}).get("hostname") or m["internal_client"]
        risky = m["internal_port"] in RISKY_EXPOSED or m["external_port"] in RISKY_EXPOSED
        unknown = not target or not target.get("trusted")
        severity = "high" if (risky or unknown) else "medium"
        if behind_nat:
            severity = "low"
        why = []
        if risky:
            why.append("la porta corrisponde a un servizio che non dovrebbe mai essere esposto")
        if unknown:
            why.append("il dispositivo di destinazione non è segnato come fidato")
        detail = (
            f"La porta {m['external_port']}/{m['protocol']} del router è inoltrata a {name} "
            f"(porta {m['internal_port']})"
            + (f", descrizione: {m['description']}" if m["description"] else "")
            + ". " + ("Attenzione: " + " e ".join(why) + "." if why else "")
        )
        fid = f"upnp-map:{m['protocol']}:{m['external_port']}"
        out.append(_finding(
            fid, severity, f"Porta {m['external_port']}/{m['protocol']} aperta verso Internet",
            detail.strip(),
            ["Se non riconosci questa apertura, chiudila con il pulsante qui sotto.",
             "Il dispositivo potrebbe riaprirla da solo: in quel caso disattiva UPnP nelle sue impostazioni o sul router."],
            target, m["external_port"], category="router",
            action={"type": "upnp_delete", "label": "Chiudi la porta",
                    "external_port": m["external_port"], "protocol": m["protocol"],
                    "remote_host": m["remote_host"]}))
    return out
