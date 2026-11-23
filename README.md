# Sentinella

Add-on per Home Assistant OS che controlla la sicurezza della rete di casa: dispositivi collegati, servizi a rischio, aperture del router. Descrizione completa in [sentinella/DOCS.md](sentinella/DOCS.md).

## Installazione su Home Assistant OS

1. Impostazioni > Add-on > Store > menu in alto a destra > **Repository**.
2. Aggiungi `https://github.com/StefanoCasali/sentinell-ha` e chiudi.
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
| `upnp.py` | Lettura e chiusura delle aperture UPnP del router |
| `rules.py` | Regole, testi dei rimedi, lista delle verifiche manuali |
| `engine.py` | Scansione, stato dei problemi, incidenti, interventi |
| `server.py`, `web/` | API e interfaccia (ingress) |
| `entities.py` | Elenco delle entità esposte a Home Assistant |
| `ha.py` | Canali verso Home Assistant: MQTT discovery, API, eventi, notifiche |
