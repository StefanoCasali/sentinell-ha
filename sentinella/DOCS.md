# Sentinella

[Italiano](DOCS.it.md)

Sentinella checks your home network from the inside and tells you what to fix.

## What it checks

- **Devices**: everything powered on in the network, with MAC address and vendor. After the first scan every new device is reported until you mark it as trusted.
- **Risky services**: about 50 typical ports (Telnet, FTP, SMB, RDP, VNC, ADB, MQTT, Redis, Docker, databases, DVRs). Where it makes sense it also verifies whether the service accepts anyone: anonymous FTP, MQTT and Redis without a password, VNC without authentication, SMBv1, open Docker API, logins over unencrypted HTTP.
- **Router**: UPnP enabled, ports opened to the Internet through UPnP, public address (or CGNAT), administration services exposed on the LAN.
- **Manual checks**: a list of router settings that no scan can read (WPS, admin password, manual port forwards, DMZ, guest network).

## What it knows about each device

Besides IP, MAC and vendor, the **Devices** tab shows what the device announces by itself on the network:

| Source | What it provides |
|---|---|
| mDNS/Bonjour | Friendly name, model, firmware and offered services (Chromecast, AirPlay, printers, HomeKit, ESPHome, Shelly...) |
| SSDP/UPnP | Manufacturer, model and type of TVs, consoles, NAS units, media players |
| NetBIOS | Computer name and workgroup |
| HTTPS certificate | Subject, whether it is self-signed, expiry (an expired certificate is reported as a low finding) |
| MAC | Whether it is random ("private"), typical of phones and tablets |

From this data a **type** is inferred (router, computer, phone, TV, audio, printer, camera, NAS, smart device, hub, console, server). It is an estimate, used to filter the list, and it can be wrong.

The `deep_scan` option adds an nmap scan of the open ports that detects the software and version behind each service and estimates the operating system. It lengthens the scan by a few minutes and is more noticeable to devices, so it is off by default. Versions are shown, not matched against a list of known vulnerabilities.

## Link with the smart home

For every network device Sentinella looks up who already knows it in Home Assistant and reports it in the card, with a link to the device page, its integrations, area and entities. Matches are searched by:

- **MAC** in the connections or identifiers of the Home Assistant device;
- **configuration URL** of the device (the "Visit" link pointing to its IP);
- **IP or MAC in entities**: the `ip`, `ip_address`, `host`, `mac`, `mac_address` attributes, or sensors whose state is the IP address (typical of ESPHome, Shelly, WLED and device trackers).

A "not linked" device is simply on the network without any integration using it: it can be normal (a phone, a TV) or a hint worth investigating. Cloud integrations that know neither IP nor MAC (Tuya, for example) cannot be recognised. Over MQTT, the `mqtt` integration may appear next to the others because Sentinella's own "Online" sensor is attached to the same device.

The registry is read at every scan; the outcome is shown in the **Status** tab. Disable it with the `ha_links` option.

## Findings and incidents

A **finding** is a state: it stays open as long as the scan detects it (or until you ignore it). An **incident** is a suspicious change between two scans and stays "to review" until you press **I have reviewed it**:

| Incident | When it fires |
|---|---|
| `new_device` | A device never seen before joins the network |
| `new_service` | A known device opens a port that was closed before |
| `exposed_port` | A new forward to the Internet appears on the router |
| `router_changed` | The router's MAC changes (router replaced, or ARP spoofing) |
| `upnp_enabled` | UPnP, previously off, is now enabled |
| `new_vulnerability` | A critical or high finding appears without a port change |

The first scan is the baseline and raises no incidents. Incidents are detected only when a scan runs: this is not real-time traffic monitoring.

## What it can fix by itself

Only UPnP forwards: the **Close the port** button asks for confirmation, sends the request to the router and reads the list again to verify that the forward is gone. For everything else each finding has a **How to fix** section with the steps to perform manually.

ISP-provided routers usually expose no configuration API: WPS, manual port forwards, DMZ and passwords can only be changed from the router's web panel.

## Entities in Home Assistant

If an MQTT broker is installed (Mosquitto add-on with the MQTT integration), entities are created through MQTT discovery under the **Sentinella** device: they have a unique ID, can be renamed and keep their state across restarts. Broker credentials are provided by the Supervisor, there is nothing to configure.

Without a broker the same entities are written through the Home Assistant API: they work in automations and dashboards, but cannot be edited from the UI and after a Home Assistant restart they reappear within 10 minutes.

| Entity | Content |
|---|---|
| `sensor.sentinella_devices_online` | Devices powered on; list and count by type in the attributes |
| `sensor.sentinella_devices_linked_to_the_smart_home` | Network devices already known to an integration; `not_linked` list in the attributes |
| `sensor.sentinella_known_devices` | Devices seen at least once |
| `sensor.sentinella_untrusted_devices` | Online and not yet classified; list in the attributes |
| `binary_sensor.sentinella_new_device_detected` | On while a new device is waiting to be classified |
| `sensor.sentinella_latest_device_seen` | Name, IP, MAC and date of the latest arrival |
| `sensor.sentinella_open_findings` | Total open findings; list and counts in the attributes |
| `sensor.sentinella_critical_findings` / `_high_` / `_medium_` / `_low_findings` | Count by severity |
| `sensor.sentinella_highest_severity` | `critical`, `high`, `medium`, `low`, `info` or `none` |
| `binary_sensor.sentinella_security_vulnerabilities` | On if there is at least one finding of medium severity or higher |
| `sensor.sentinella_security_score` | From 0 to 100: goes down with findings, incidents and unclassified devices |
| `binary_sensor.sentinella_security_incident` | On while an incident is waiting to be reviewed |
| `sensor.sentinella_incidents_to_review` | Number of incidents; list in the attributes |
| `sensor.sentinella_latest_incident` | Title, date, severity, type and detail |
| `sensor.sentinella_ports_open_to_the_internet` | UPnP forwards; list in the attributes |
| `binary_sensor.sentinella_upnp_enabled_on_the_router` | UPnP status |
| `sensor.sentinella_public_ip_address` | WAN address declared by the router |
| `sensor.sentinella_manual_checks_completed` | Ticked items of the router checklist; missing ones in the attributes |
| `sensor.sentinella_last_scan`, `_last_scan_duration`, `binary_sensor.sentinella_scan_in_progress` | Diagnostics |
| `binary_sensor.<device>_online` | One per device: on or off, with IP, MAC, type, model, operating system, open ports, findings and the smart home references (`linked_to_home_assistant`, `ha_devices`, `ha_integrations`, `ha_entities`) |

Entity IDs above are those of an English installation over MQTT; in Italian they derive from the Italian entity name. Attribute keys are always in English and do not change with the language. With the API channel the IDs are fixed: `sensor.sentinella_<id>` (for example `sensor.sentinella_dispositivi_online`, `binary_sensor.sentinella_falle`, `binary_sensor.sentinella_dispositivo_<mac>`).

Over MQTT the per-device sensors are attached, through the MAC, to the device already present in Home Assistant if another integration knows it. Turn them off with the `device_entities` option.

Every incident also fires the `sentinella_incident` event (fields `type`, `severity`, `title`, `detail`, `device`, `ip`), handy as a trigger:

```yaml
automation:
  - alias: Network incident alert
    trigger:
      - platform: event
        event_type: sentinella_incident
    action:
      - service: notify.notify
        data:
          title: "Sentinella: {{ trigger.event.data.title }}"
          message: "{{ trigger.event.data.detail }}"
```

## Limits you should know

- The scan runs **from the inside**: it sees what is exposed on the LAN, not what is reachable from the Internet. Forwards to the outside are known only through UPnP and the manual review of port forwards.
- It only sees the network Home Assistant is connected to. An isolated guest network or a separate VLAN cannot be reached.
- It does not try factory passwords and does not exploit vulnerabilities: checks are a single read-only connection.
- Devices with a random MAC (phones) can show up as new again when their address changes: disable the private MAC for your home network or mark them as trusted again.

## Options

| Option | Default | Meaning |
|---|---|---|
| `scan_interval_hours` | 6 | Hours between one automatic scan and the next |
| `networks` | empty | Networks to check (e.g. `192.168.1.0/24`). Empty: the host's network |
| `extra_ports` | empty | Additional ports to check |
| `active_probes` | on | Verify whether services accept access without a password |
| `notify` | on | Home Assistant notification for every incident |
| `device_entities` | on | Create an "Online" sensor for every device |
| `ha_links` | on | Look up devices and entities already linked in Home Assistant |
| `deep_scan` | off | Service versions and operating system with nmap (slower) |
| `language` | `auto` | Language of the panel, findings, incidents and entity names: `auto` follows Home Assistant (Italian or English) |
| `mqtt_host`, `mqtt_port`, `mqtt_username`, `mqtt_password` | empty | Only for a broker other than the Mosquitto add-on |

Write networks with their mask (`192.168.1.0/24`); without a mask `/24` is assumed.

## If the sensors do not show up

Open the **Status** tab of the panel: the first card says which channel is in use (MQTT, API or none), how many entities were published and, if MQTT cannot be used, why. The same information is in the add-on log, in the `Sensors to Home Assistant` line.

- **MQTT channel**: entities are under Settings > Devices & services > MQTT, device "Sentinella".
- **API channel**: there is no device; search for `sentinella` in Developer tools > States.
- To switch to MQTT you need the Mosquitto add-on running with the MQTT integration configured, or the `mqtt_*` options for another broker.

## First scan

At the first scan every device is "to classify" without raising alerts. Go through the **Devices** tab, name the ones you recognise and mark them as trusted: from then on every new arrival is reported.
