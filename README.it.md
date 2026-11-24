# Sentinella

Add-on per Home Assistant OS che controlla la sicurezza della rete di casa: dispositivi collegati, servizi a rischio, aperture del router. Descrizione completa in [sentinella/DOCS.it.md](sentinella/DOCS.it.md). [English](README.md)

## Installazione su Home Assistant OS

[![Open your Home Assistant instance and show the add app repository dialog with a specific repository URL pre-filled.](https://my.home-assistant.io/badges/supervisor_add_addon_repository.svg)](https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2FStefanoCasali%2Fsentinell-ha)

Il pulsante apre il tuo Home Assistant con il repository già compilato. In alternativa, a mano:

1. Impostazioni > Add-on > Store > menu in alto a destra > **Repository**.
2. Aggiungi `https://github.com/StefanoCasali/sentinell-ha` e chiudi.

Poi:

3. Apri **Sentinella** nell'elenco, premi **Installa** (l'immagine viene costruita sul tuo Home Assistant: qualche minuto) e poi **Avvia**.
4. Attiva **Mostra nella barra laterale**.

Gli aggiornamenti compaiono quando cambia `version` in `sentinella/config.yaml`.

In alternativa, come add-on locale: copia la cartella `sentinella/` nella condivisione `addons` di Home Assistant (add-on Samba share) e premi **Controlla aggiornamenti** nello Store.

## Sviluppo

Serve solo Python 3.11+, nessuna dipendenza:

```bash
python sentinella/app/dev.py
```

L'interfaccia è su http://127.0.0.1:8099. Stato e opzioni stanno in `sentinella/app/.devdata/`; con `{"networks": ["127.0.0.1/32"]}` in `options.json` la scansione resta sul computer locale. Senza nmap la scoperta usa ping e tabella ARP (niente produttore).

## Struttura

| File | Ruolo |
|---|---|
| `discovery.py` | Dispositivi accesi (nmap ARP, riserva ping + ARP) |
| `portscan.py` | Scansione TCP delle porte |
| `probes.py` | Verifiche non distruttive sui servizi |
| `enrich.py` | Identificazione dei dispositivi: mDNS, SSDP, NetBIOS, nmap approfondito, tipo |
| `halink.py` | Legge da Home Assistant dispositivi, entità e il loro stato di salute |
| `smarthome.py` | Analisi delle reti Zigbee, Z-Wave, Matter, Bluetooth e MQTT |
| `accesslog.py` | Accessi falliti e indirizzi bloccati dal log di Home Assistant |
| `upnp.py` | Lettura e chiusura delle aperture UPnP del router |
| `rules.py` | Regole, testi dei rimedi, lista delle verifiche manuali |
| `engine.py` | Scansione, stato dei problemi, incidenti, interventi |
| `server.py`, `web/` | API e interfaccia (ingress) |
| `entities.py` | Elenco delle entità esposte a Home Assistant |
| `i18n.py` | Testi in italiano e inglese |
| `ha.py` | Canali verso Home Assistant: MQTT discovery, API, eventi, notifiche |
