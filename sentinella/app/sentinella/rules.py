"""Regole: trasformano ciò che la scansione ha visto in problemi con rimedio."""

import ipaddress

from .i18n import L, s, t

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


DB_DETAIL = L("Un database dovrebbe ascoltare in rete solo se altri dispositivi devono davvero collegarsi.",
              "A database should listen on the network only if other devices really need to connect to it.")

# porta -> (gravità, titolo, perché è un problema, passi per rimediare)
PORT_RULES = {
    23: ("high", L("Telnet attivo", "Telnet enabled"),
         L("Telnet trasmette utente e password in chiaro ed è il bersaglio principale dei malware per dispositivi IoT.",
           "Telnet sends usernames and passwords in clear text and is the main target of IoT malware."),
         [L("Entra nel pannello del dispositivo e disattiva Telnet.", "Open the device's admin panel and disable Telnet."),
          L("Se serve l'accesso remoto, usa SSH con una password robusta.",
            "If you need remote access, use SSH with a strong password."),
          L("Se non si può disattivare, aggiorna il firmware o sposta il dispositivo sulla rete ospiti.",
            "If it cannot be disabled, update the firmware or move the device to the guest network.")]),
    21: ("medium", L("FTP attivo", "FTP enabled"),
         L("FTP trasmette credenziali e file in chiaro: chiunque sia in rete può intercettarli.",
           "FTP sends credentials and files in clear text: anyone on the network can intercept them."),
         [L("Disattiva il server FTP dal pannello del dispositivo.", "Disable the FTP server from the device's admin panel."),
          L("Per scambiare file usa SFTP o una condivisione SMB protetta da password.",
            "To exchange files use SFTP or a password-protected SMB share.")]),
    139: ("low", L("Condivisione NetBIOS attiva", "NetBIOS sharing enabled"),
          L("Servizio di condivisione Windows datato, utile solo a dispositivi molto vecchi.",
            "Legacy Windows sharing service, only useful for very old devices."),
          [L("Se non hai dispositivi che lo richiedono, disattiva NetBIOS su TCP/IP nelle impostazioni di rete.",
             "If no device needs it, disable NetBIOS over TCP/IP in the network settings.")]),
    445: ("low", L("Condivisione file SMB attiva", "SMB file sharing enabled"),
          L("Normale su PC e NAS, ma ogni cartella condivisa va protetta da password.",
            "Normal on PCs and NAS units, but every shared folder must be password protected."),
          [L("Verifica che non ci siano cartelle condivise con 'Everyone' o accesso ospite.",
             "Check that no folder is shared with 'Everyone' or with guest access."),
           L("Disattiva la condivisione file se su questo dispositivo non la usi.",
             "Disable file sharing if you don't use it on this device.")]),
    3389: ("medium", L("Desktop remoto (RDP) attivo", "Remote Desktop (RDP) enabled"),
           L("RDP è tra i servizi più attaccati: basta una password debole per perdere il controllo del PC.",
             "RDP is one of the most attacked services: a weak password is enough to lose control of the PC."),
           [L("Se non lo usi: Impostazioni > Sistema > Desktop remoto > disattiva.",
              "If you don't use it: Settings > System > Remote Desktop > turn off."),
            L("Se lo usi: password robusta, autenticazione a livello di rete e mai un port forwarding diretto.",
              "If you use it: strong password, Network Level Authentication and never a direct port forward.")]),
    5900: ("medium", L("VNC attivo", "VNC enabled"),
           L("VNC dà il controllo completo dello schermo e spesso non cifra il traffico.",
             "VNC gives full control of the screen and often does not encrypt traffic."),
           [L("Disattiva VNC se non serve.", "Disable VNC if you don't need it."),
            L("Altrimenti imposta una password robusta e usalo solo via VPN.",
              "Otherwise set a strong password and use it only through a VPN.")]),
    5555: ("critical", L("Android Debug Bridge (ADB) aperto in rete", "Android Debug Bridge (ADB) open on the network"),
           L("Chiunque in rete può installare app ed eseguire comandi sul dispositivo senza password.",
             "Anyone on the network can install apps and run commands on the device without a password."),
           [L("Sul dispositivo: Impostazioni > Opzioni sviluppatore > disattiva 'Debug ADB' / 'Debug di rete'.",
              "On the device: Settings > Developer options > turn off 'ADB debugging' / 'Network debugging'."),
            L("Su TV box economici, se l'opzione non esiste, isola il dispositivo sulla rete ospiti.",
              "On cheap TV boxes, if the option is missing, isolate the device on the guest network.")]),
    1883: ("low", L("Broker MQTT attivo", "MQTT broker running"),
           L("MQTT sulla porta 1883 non è cifrato: comandi e stati della domotica viaggiano in chiaro.",
             "MQTT on port 1883 is not encrypted: smart home commands and states travel in clear text."),
           [L("Assicurati che il broker richieda utente e password.", "Make sure the broker requires a username and password."),
            L("Non esporre mai questa porta verso Internet.", "Never expose this port to the Internet.")]),
    6379: ("medium", L("Redis raggiungibile in rete", "Redis reachable on the network"),
           L("Redis non è pensato per essere esposto: senza password permette di leggere e scrivere tutti i dati.",
             "Redis is not meant to be exposed: without a password anyone can read and write all its data."),
           [L("Configura 'bind 127.0.0.1' oppure imposta 'requirepass' nella configurazione di Redis.",
              "Set 'bind 127.0.0.1' or configure 'requirepass' in the Redis configuration.")]),
    2375: ("medium", L("Porta dell'API Docker aperta", "Docker API port open"),
           L("L'API Docker senza TLS equivale a un accesso da amministratore alla macchina.",
             "The Docker API without TLS is equivalent to administrator access to the machine."),
           [L("Rimuovi '-H tcp://0.0.0.0:2375' dalla configurazione del demone Docker.",
              "Remove '-H tcp://0.0.0.0:2375' from the Docker daemon configuration."),
            L("Se serve l'accesso remoto usa SSH oppure TLS con certificati client (porta 2376).",
              "If you need remote access use SSH or TLS with client certificates (port 2376).")]),
    9200: ("medium", L("Elasticsearch raggiungibile in rete", "Elasticsearch reachable on the network"),
           L("Senza autenticazione chiunque in rete può leggere e cancellare gli indici.",
             "Without authentication anyone on the network can read and delete the indices."),
           [L("Limita l'ascolto a localhost (network.host) oppure attiva la sicurezza integrata.",
              "Restrict listening to localhost (network.host) or enable the built-in security features.")]),
    27017: ("medium", L("MongoDB raggiungibile in rete", "MongoDB reachable on the network"),
            L("Le installazioni senza autenticazione espongono tutti i dati.",
              "Installations without authentication expose all their data."),
            [L("Imposta bindIp a 127.0.0.1 oppure attiva l'autenticazione.",
               "Set bindIp to 127.0.0.1 or enable authentication.")]),
    11211: ("medium", L("Memcached raggiungibile in rete", "Memcached reachable on the network"),
            L("Memcached non ha autenticazione: i dati in cache sono leggibili da chiunque.",
              "Memcached has no authentication: cached data can be read by anyone."),
            [L("Limita l'ascolto a 127.0.0.1 (opzione -l).", "Restrict listening to 127.0.0.1 (option -l).")]),
    3306: ("low", L("MySQL/MariaDB raggiungibile in rete", "MySQL/MariaDB reachable on the network"), DB_DETAIL,
           [L("Se lo usa solo la macchina stessa, imposta bind-address = 127.0.0.1.",
              "If only the machine itself uses it, set bind-address = 127.0.0.1."),
            L("Verifica che non esistano utenti senza password.", "Check that there are no users without a password.")]),
    5432: ("low", L("PostgreSQL raggiungibile in rete", "PostgreSQL reachable on the network"), DB_DETAIL,
           [L("Limita listen_addresses e pg_hba.conf agli indirizzi che ne hanno bisogno.",
              "Restrict listen_addresses and pg_hba.conf to the addresses that need it.")]),
    1433: ("low", L("SQL Server raggiungibile in rete", "SQL Server reachable on the network"), DB_DETAIL,
           [L("Se è un'istanza di sviluppo, disattiva il protocollo TCP/IP o limita il firewall alla rete locale.",
              "If it is a development instance, disable the TCP/IP protocol or restrict the firewall to the local network."),
            L("Verifica che l'utente 'sa' sia disattivato o abbia una password robusta.",
              "Check that the 'sa' user is disabled or has a strong password.")]),
    1723: ("medium", L("Server VPN PPTP attivo", "PPTP VPN server enabled"),
           L("PPTP è un protocollo VPN considerato violabile da anni.",
             "PPTP is a VPN protocol that has been considered broken for years."),
           [L("Disattiva PPTP e passa a WireGuard o OpenVPN.", "Disable PPTP and switch to WireGuard or OpenVPN.")]),
    37777: ("medium", L("Porta di gestione DVR/telecamera aperta", "DVR/camera management port open"),
            L("I videoregistratori economici hanno una lunga storia di falle e accessi di fabbrica.",
              "Cheap video recorders have a long history of vulnerabilities and factory backdoor accounts."),
            [L("Aggiorna il firmware e cambia la password di fabbrica.", "Update the firmware and change the factory password."),
             L("Disattiva l'accesso cloud/P2P se non lo usi e non aprire mai questa porta verso Internet.",
               "Disable cloud/P2P access if you don't use it and never open this port to the Internet.")]),
    554: ("low", L("Flusso video RTSP attivo", "RTSP video stream enabled"),
          L("Il video della telecamera è accessibile in rete: va protetto da password.",
            "The camera video is reachable on the network: it must be password protected."),
          [L("Verifica che il flusso RTSP richieda credenziali e che non siano quelle di fabbrica.",
             "Check that the RTSP stream requires credentials and that they are not the factory ones.")]),
    2049: ("low", L("Condivisione NFS attiva", "NFS share enabled"),
           L("NFS si fida degli indirizzi IP: qualunque dispositivo in rete può potenzialmente montare le cartelle.",
             "NFS trusts IP addresses: any device on the network can potentially mount the folders."),
           [L("Limita le esportazioni NFS ai soli indirizzi che ne hanno bisogno.",
              "Restrict NFS exports to the addresses that actually need them.")]),
    873: ("low", L("Servizio rsync attivo", "rsync service running"),
          L("I moduli rsync senza autenticazione permettono di leggere o sovrascrivere file.",
            "rsync modules without authentication allow files to be read or overwritten."),
          [L("Proteggi i moduli con 'auth users' oppure disattiva il demone rsync.",
             "Protect the modules with 'auth users' or disable the rsync daemon.")]),
}
PORT_RULES[2323] = PORT_RULES[23]
PORT_RULES[5901] = PORT_RULES[5900]
PORT_RULES[34567] = PORT_RULES[37777]

# Controlli che nessuna scansione dall'interno può fare: li conferma l'utente.
ROUTER_CHECKLIST = [
    {"id": "admin_password",
     "title": L("Password di amministrazione del router cambiata", "Router admin password changed"),
     "why": L("La password stampata sull'etichetta o quella di fabbrica è nota a chiunque abbia avuto il router in mano.",
              "The password printed on the label, or the factory one, is known to anyone who has handled the router."),
     "how": L("Pannello del router > Gestione/Amministrazione > Account utente: imposta una password lunga e unica.",
              "Router panel > Management/Administration > User account: set a long, unique password.")},
    {"id": "wps_off", "title": L("WPS disattivato", "WPS disabled"),
     "why": L("Il PIN WPS si forza in poche ore e consegna la password del Wi-Fi.",
              "The WPS PIN can be brute-forced in a few hours and reveals the Wi-Fi password."),
     "how": L("Pannello del router > Rete locale > WLAN > WPS: disattivalo su entrambe le bande.",
              "Router panel > Local network > WLAN > WPS: disable it on both bands.")},
    {"id": "wifi_wpa",
     "title": L("Wi-Fi in WPA2-AES o WPA3 con password robusta", "Wi-Fi on WPA2-AES or WPA3 with a strong password"),
     "why": L("WEP e WPA/TKIP sono violabili; una password corta si indovina con un attacco a dizionario.",
              "WEP and WPA/TKIP can be broken; a short password can be guessed with a dictionary attack."),
     "how": L("Pannello del router > WLAN > Sicurezza: scegli WPA2-PSK (AES) o WPA2/WPA3 e una password di almeno 16 caratteri.",
              "Router panel > WLAN > Security: choose WPA2-PSK (AES) or WPA2/WPA3 and a password of at least 16 characters.")},
    {"id": "remote_mgmt_off",
     "title": L("Gestione remota dal lato Internet disattivata", "Remote management from the Internet disabled"),
     "why": L("Il pannello del router non deve essere raggiungibile da Internet.",
              "The router's admin panel must not be reachable from the Internet."),
     "how": L("Pannello del router > Sicurezza/Gestione > Accesso remoto (o 'Controllo servizi'): nessun servizio abilitato sul lato WAN.",
              "Router panel > Security/Management > Remote access (or 'Service control'): no service enabled on the WAN side.")},
    {"id": "port_forwarding",
     "title": L("Port forwarding manuali verificati", "Manual port forwards reviewed"),
     "why": L("Le aperture inserite a mano non sono leggibili via UPnP: vanno controllate nel pannello.",
              "Manually created forwards cannot be read through UPnP: they must be checked in the panel."),
     "how": L("Pannello del router > Internet > Sicurezza > Port forwarding (o 'Server virtuale'): elimina le regole che non riconosci.",
              "Router panel > Internet > Security > Port forwarding (or 'Virtual server'): delete the rules you don't recognise.")},
    {"id": "dmz_off", "title": L("DMZ disattivata", "DMZ disabled"),
     "why": L("La DMZ espone a Internet tutte le porte di un dispositivo.",
              "The DMZ exposes every port of one device to the Internet."),
     "how": L("Pannello del router > Internet > Sicurezza > DMZ: disattivata.",
              "Router panel > Internet > Security > DMZ: disabled.")},
    {"id": "upnp_off", "title": L("UPnP disattivato (se non serve)", "UPnP disabled (if not needed)"),
     "why": L("Con UPnP qualunque dispositivo o malware in rete può aprirsi porte verso Internet da solo.",
              "With UPnP any device or malware on the network can open ports to the Internet by itself."),
     "how": L("Pannello del router > Rete locale > UPnP: disattivalo. Riattivalo solo se console o videochiamate smettono di funzionare.",
              "Router panel > Local network > UPnP: disable it. Re-enable it only if game consoles or video calls stop working.")},
    {"id": "guest_network", "title": L("Dispositivi IoT sulla rete ospiti", "IoT devices on the guest network"),
     "why": L("Telecamere, prese e TV economiche sono i dispositivi meno aggiornati: separarli protegge PC e telefoni.",
              "Cameras, plugs and cheap TVs are the least updated devices: separating them protects PCs and phones."),
     "how": L("Pannello del router > WLAN > Rete ospiti: attivala con isolamento dalla LAN e spostaci i dispositivi smart.",
              "Router panel > WLAN > Guest network: enable it with LAN isolation and move the smart devices there.")},
    {"id": "firmware", "title": L("Firmware del router aggiornato", "Router firmware up to date"),
     "why": L("Sui router dell'operatore gli aggiornamenti arrivano da remoto, ma solo se il router resta acceso e collegato.",
              "On ISP-provided routers updates are pushed remotely, but only if the router stays powered on and connected."),
     "how": L("Pannello del router > Gestione > Informazioni dispositivo: annota la versione e confrontala con quella indicata dall'assistenza dell'operatore.",
              "Router panel > Management > Device information: note the version and compare it with the one stated by your ISP's support.")},
]


def checklist() -> list[dict]:
    """Lista delle verifiche manuali nella lingua corrente."""
    return [{k: s(v) for k, v in item.items()} for item in ROUTER_CHECKLIST]


def _finding(fid, severity, title, detail, steps, device=None, port=None, category="servizio", action=None):
    return {
        "id": fid, "severity": severity, "title": s(title), "detail": s(detail),
        "remediation": s(steps), "category": category, "port": port, "action": action,
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
            f"new-device:{key}", "medium", t("Nuovo dispositivo in rete", "New device on the network"),
            t("Questo dispositivo non era presente nelle scansioni precedenti.",
              "This device was not present in previous scans."),
            [t("Se lo riconosci, segnalo come fidato dalla scheda Dispositivi.",
               "If you recognise it, mark it as trusted from the Devices tab."),
             t("Se non lo riconosci, cambia la password del Wi-Fi e controlla l'elenco dei dispositivi collegati sul router.",
               "If you don't recognise it, change the Wi-Fi password and check the list of connected devices on the router.")],
            device, category="dispositivo"))

    for entry in device.get("ports", []):
        port, info = entry["port"], entry.get("info", {})
        if info.get("cert_expired"):
            out.append(_finding(
                f"cert-expired:{key}:{port}", "low", t("Certificato HTTPS scaduto", "Expired HTTPS certificate"),
                t("Il certificato presentato sulla porta {port} è scaduto: il browser non può più garantire "
                  "che tu stia parlando con il dispositivo giusto.",
                  "The certificate presented on port {port} has expired: the browser can no longer guarantee "
                  "that you are talking to the right device.").format(port=port),
                [t("Rigenera il certificato dal pannello del dispositivo o aggiorna il firmware.",
                   "Regenerate the certificate from the device's panel or update the firmware."),
                 t("Se il dispositivo non lo permette, raggiungilo solo dalla rete di casa.",
                   "If the device does not allow it, reach it only from your home network.")],
                device, port))
        rule = PORT_RULES.get(port)
        if rule:
            severity, title, detail, steps = rule
            title, detail = s(title), s(detail)
            if port == 21 and info.get("anonymous"):
                severity, title = "high", t("FTP con accesso anonimo", "FTP with anonymous access")
                detail = t("Il server FTP accetta l'utente 'anonymous' senza password: i file sono leggibili da chiunque in rete.",
                           "The FTP server accepts the 'anonymous' user without a password: files can be read by anyone on the network.")
            elif port == 445 and info.get("smbv1"):
                severity, title = "high", t("Protocollo SMBv1 attivo", "SMBv1 protocol enabled")
                detail = t("SMBv1 è il protocollo sfruttato da WannaCry e da molti altri malware; è obsoleto dal 2017.",
                           "SMBv1 is the protocol exploited by WannaCry and many other malware families; it has been obsolete since 2017.")
                steps = [t("Windows: 'Attiva o disattiva funzionalità di Windows' > togli 'Supporto per condivisione file SMB 1.0/CIFS'.",
                           "Windows: 'Turn Windows features on or off' > untick 'SMB 1.0/CIFS File Sharing Support'."),
                         t("NAS: imposta SMB2 come protocollo minimo nelle impostazioni dei servizi file.",
                           "NAS: set SMB2 as the minimum protocol in the file services settings.")]
            elif port in (5900, 5901) and info.get("noauth"):
                severity, title = "critical", t("VNC senza password", "VNC without a password")
                detail = t("Il server VNC accetta connessioni senza autenticazione: chiunque in rete controlla lo schermo.",
                           "The VNC server accepts connections without authentication: anyone on the network controls the screen.")
            elif port == 1883 and info.get("anonymous"):
                severity, title = "high", t("Broker MQTT senza autenticazione", "MQTT broker without authentication")
                detail = t("Il broker accetta connessioni anonime: chiunque in rete può leggere gli stati e inviare comandi ai dispositivi.",
                           "The broker accepts anonymous connections: anyone on the network can read states and send commands to devices.")
                steps = [t("Mosquitto: imposta 'allow_anonymous false' e crea gli utenti con mosquitto_passwd.",
                           "Mosquitto: set 'allow_anonymous false' and create users with mosquitto_passwd."),
                         t("Add-on Mosquitto di Home Assistant: usa solo utenti di Home Assistant o i login definiti nell'add-on.",
                           "Home Assistant Mosquitto add-on: use only Home Assistant users or the logins defined in the add-on.")]
            elif port == 6379 and info.get("noauth"):
                severity, title = "high", t("Redis senza password", "Redis without a password")
            elif port == 2375 and info.get("docker_api"):
                severity, title = "critical", t("API Docker aperta senza autenticazione", "Docker API open without authentication")
            elif port == 9200 and info.get("open_elasticsearch"):
                severity, title = "high", t("Elasticsearch senza autenticazione", "Elasticsearch without authentication")
            if device.get("is_gateway") and port in (23, 2323, 21):
                severity = _bump(severity, "high")
                title += t(" sul router", " on the router")
            out.append(_finding(f"port:{key}:{port}", severity, title, detail, steps, device, port))
        elif info.get("auth") == "basic" and not info.get("tls"):
            out.append(_finding(
                f"http-basic:{key}:{port}", "medium", t("Login su HTTP non cifrato", "Login over unencrypted HTTP"),
                t("La pagina chiede utente e password senza HTTPS: le credenziali viaggiano in chiaro a ogni richiesta.",
                  "The page asks for a username and password without HTTPS: credentials travel in clear text on every request."),
                [t("Attiva HTTPS nel pannello del dispositivo, se disponibile.",
                   "Enable HTTPS in the device's panel, if available."),
                 t("Non riutilizzare su questo dispositivo una password usata altrove.",
                   "Do not reuse on this device a password you use elsewhere.")],
                device, port))
        elif device.get("is_gateway") and port == 22:
            out.append(_finding(
                f"port:{key}:22", "low", t("SSH attivo sul router", "SSH enabled on the router"),
                t("L'accesso SSH al router serve di rado in casa e amplia la superficie d'attacco.",
                  "SSH access to the router is rarely needed at home and widens the attack surface."),
                [t("Se non lo usi, disattivalo dal pannello del router (Gestione > Controllo servizi).",
                   "If you don't use it, disable it from the router's panel (Management > Service control).")],
                device, port))
    return out


def router_findings(upnp: dict, devices_by_ip: dict) -> list[dict]:
    out = []
    if not upnp.get("available"):
        return out
    out.append(_finding(
        "upnp-enabled", "medium", t("UPnP attivo sul router", "UPnP enabled on the router"),
        t("Qualunque dispositivo (o malware) nella rete può aprire porte verso Internet senza chiedere conferma.",
          "Any device (or malware) on the network can open ports to the Internet without asking for confirmation."),
        [t("Pannello del router > Rete locale > UPnP: disattivalo.", "Router panel > Local network > UPnP: disable it."),
         t("Se console di gioco o videochiamate smettono di funzionare, riattivalo e tieni d'occhio questo elenco.",
           "If game consoles or video calls stop working, re-enable it and keep an eye on this list.")],
        category="router"))

    ext = upnp.get("external_ip")
    behind_nat = is_behind_nat(ext)
    if behind_nat:
        out.append(_finding(
            "wan-private", "info", t("Il router non ha un indirizzo pubblico", "The router has no public address"),
            t("L'indirizzo WAN ({ip}) è privato: sei dietro il NAT dell'operatore (CGNAT) o un secondo router. "
              "Le porte aperte qui sotto non sono raggiungibili direttamente da Internet.",
              "The WAN address ({ip}) is private: you are behind your ISP's NAT (CGNAT) or a second router. "
              "The open ports below are not directly reachable from the Internet.").format(ip=ext),
            [t("Nessun intervento necessario: è una protezione in più.", "No action needed: it is an extra layer of protection.")],
            category="router"))

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
            why.append(t("la porta corrisponde a un servizio che non dovrebbe mai essere esposto",
                         "the port belongs to a service that should never be exposed"))
        if unknown:
            why.append(t("il dispositivo di destinazione non è segnato come fidato",
                         "the target device is not marked as trusted"))
        port_label = f"{m['external_port']}/{m['protocol']}"
        detail = t("La porta {port} del router è inoltrata a {name} (porta {inner})",
                   "Router port {port} is forwarded to {name} (port {inner})").format(
                       port=port_label, name=name, inner=m["internal_port"])
        if m["description"]:
            detail += t(", descrizione: {d}", ", description: {d}").format(d=m["description"])
        detail += "."
        if why:
            detail += " " + t("Attenzione: ", "Warning: ") + t(" e ", " and ").join(why) + "."
        out.append(_finding(
            f"upnp-map:{m['protocol']}:{m['external_port']}", severity,
            t("Porta {port} aperta verso Internet", "Port {port} open to the Internet").format(port=port_label),
            detail,
            [t("Se non riconosci questa apertura, chiudila con il pulsante qui sotto.",
               "If you don't recognise this forward, close it with the button below."),
             t("Il dispositivo potrebbe riaprirla da solo: in quel caso disattiva UPnP nelle sue impostazioni o sul router.",
               "The device may reopen it by itself: in that case disable UPnP in its settings or on the router.")],
            target, m["external_port"], category="router",
            action={"type": "upnp_delete", "label": t("Chiudi la porta", "Close the port"),
                    "external_port": m["external_port"], "protocol": m["protocol"],
                    "remote_host": m["remote_host"]}))
    return out
