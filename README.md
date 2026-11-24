# Sentinella

[Italiano](README.it.md)

Home Assistant add-on that checks the security of your home network: connected devices, risky services, router exposure and suspicious changes between scans. Full description in [sentinella/DOCS.md](sentinella/DOCS.md).

- Discovers every device and identifies it (name, model, type) through mDNS, SSDP and NetBIOS.
- Scans risky ports and verifies, without intrusion, whether services accept anyone.
- Reads the ports the router opened to the Internet through UPnP and closes them on confirmation.
- Reports incidents: new devices, newly opened ports, new forwards to the Internet.
- Shows which network devices are already linked to a Home Assistant integration.
- Watches the smart home networks (Zigbee, Z-Wave, Matter, Bluetooth, MQTT): devices not communicating, low batteries, weak signal, new devices.
- Reports failed login attempts to Home Assistant and banned addresses.
- Publishes sensors and events to Home Assistant through MQTT discovery or the API.
- Panel, findings and entity names in English or Italian.

## Installation on Home Assistant OS

[![Open your Home Assistant instance and show the add app repository dialog with a specific repository URL pre-filled.](https://my.home-assistant.io/badges/supervisor_add_addon_repository.svg)](https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2FStefanoCasali%2Fsentinell-ha)

The button opens your Home Assistant with the repository already filled in. Alternatively, by hand:

1. Settings > Add-ons > Add-on store > menu in the top right > **Repositories**.
2. Add `https://github.com/StefanoCasali/sentinell-ha` and close.

Then:

3. Open **Sentinella** in the list, press **Install** (the image is built on your Home Assistant: a few minutes) and then **Start**.
4. Enable **Show in sidebar**.

Updates show up when `version` changes in `sentinella/config.yaml`.

As a local add-on instead: copy the `sentinella/` folder into the `addons` share of Home Assistant (Samba share add-on) and press **Check for updates** in the store.

## Development

Only Python 3.11+ is needed, no dependencies:

```bash
python sentinella/app/dev.py
```

The interface is at http://127.0.0.1:8099. State and options live in `sentinella/app/.devdata/`; with `{"networks": ["127.0.0.1/32"]}` in `options.json` the scan stays on the local computer, and `"language": "it"` switches to Italian. Without nmap discovery falls back to ping and the ARP table (no vendor).

## Structure

| File | Role |
|---|---|
| `discovery.py` | Devices online (nmap ARP, fallback ping + ARP) |
| `portscan.py` | TCP port scan |
| `probes.py` | Non-destructive service checks |
| `enrich.py` | Device identification: mDNS, SSDP, NetBIOS, deep nmap, type |
| `halink.py` | Reads devices, entities and their health from Home Assistant |
| `smarthome.py` | Zigbee, Z-Wave, Matter, Bluetooth and MQTT analysis |
| `accesslog.py` | Failed logins and banned addresses from the Home Assistant log |
| `upnp.py` | Reading and closing the router's UPnP forwards |
| `rules.py` | Rules, remediation texts, manual checklist |
| `engine.py` | Scan, finding state, incidents, actions |
| `server.py`, `web/` | API and interface (ingress) |
| `entities.py` | List of the entities exposed to Home Assistant |
| `i18n.py` | Italian and English texts |
| `ha.py` | Channels to Home Assistant: MQTT discovery, API, events, notifications |
