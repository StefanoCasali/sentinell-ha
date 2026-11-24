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

## Smart home networks

Besides the local network, Sentinella analyses the networks of your smart home. Each one is a separate section of the panel: **Zigbee** (ZHA, Zigbee2MQTT, deCONZ), **Z-Wave** (Z-Wave JS), **Matter**, **Bluetooth** and **MQTT**. Devices are not queried directly: Sentinella reads what Home Assistant already knows (devices, entities and their state), so nothing else needs to be installed. A section stays empty until Home Assistant has at least one device of that kind.

Each section has its own checkbox in the add-on options (`monitor_zigbee`, `monitor_zwave`, `monitor_matter`, `monitor_bluetooth`, `monitor_mqtt`): turn off the ones you do not use. A section that is off disappears from the panel, its open findings are closed, its incidents are marked as reviewed and its sensors are removed from Home Assistant.

A device belongs to exactly one section, so nothing is reported twice. Zigbee2MQTT devices technically reach Home Assistant through MQTT: with `zigbee2mqtt_in_zigbee` on (the default) they are shown under Zigbee and the MQTT section contains only what does not come from Zigbee2MQTT; with the option off they are counted under MQTT. The same rule applies to Z-Wave devices bridged over MQTT by Z-Wave JS UI.

Every 30 minutes (option `health_interval_minutes`), independently of the network scan, it checks:

| Check | When it is reported |
|---|---|
| Device unreachable | All its entities are unavailable, or the Z-Wave node is marked dead |
| Coordinator not responding | The bridge or coordinator is unavailable (high severity: the whole network is down) |
| Device no longer reporting | A battery-powered device has sent nothing for `silent_hours` (48 by default) |
| Battery running low | Battery at or below `battery_threshold` (20% by default), or the device's own low-battery flag |
| Weak signal | Zigbee link quality below 25, or signal below -88 dBm |
| Firmware update available | Home Assistant offers an update for the device |
| Zigbee pairing left open | Zigbee2MQTT is still accepting new devices |

Changes between one check and the next become incidents: `new_device` (a device appears in a network), `device_offline` (a device stops responding), `network_outage` (most of a network goes down at once), `battery_drop` (30 points or more lost since the last check) and `device_removed`.

Things to know:

- "No longer reporting" is evaluated only for battery-powered devices: a mains-powered plug nobody uses can stay silent for days without anything being wrong.
- After a Home Assistant restart the "last report" times start again from the restart.
- Link quality and signal are checked only if the corresponding sensor is enabled in Home Assistant (Zigbee2MQTT disables `linkquality` by default).
- Devices of other integrations (Wi-Fi, cloud) are not part of any section; they appear in the local network if they have an IP address.

## Access to Home Assistant

The **Access** section watches who tries to get into Home Assistant. At every check Sentinella reads the Home Assistant log through the Supervisor and looks for requests with invalid credentials and for addresses Home Assistant has banned.

- Every source address with failed attempts becomes a `failed_login` incident: high severity if it comes from the Internet or if there are 5 or more attempts, medium otherwise. A local address is matched to the device found by the network scan, when known.
- An address banned by Home Assistant becomes an `ip_banned` incident.
- While there are failed attempts in the last 24 hours a finding stays open, with the steps to protect access (multi-factor authentication, `ip_ban_enabled`, no direct exposure of port 8123).
- If the external URL configured in Home Assistant uses plain HTTP, a high finding is reported.

Things to know:

- This needs the add-on permission to read the Home Assistant log (`hassio_role: homeassistant`); Home Assistant shows it when you update. Turn the check off with the `monitor_access` option.
- Only what is still in the log when the check runs is seen: on a very chatty installation old lines may scroll away between two checks.
- Successful logins are not written to the log, so they cannot be reported.
- Behind a reverse proxy without `use_x_forwarded_for` and `trusted_proxies`, every attempt appears to come from the proxy.


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
| `sensor.sentinella_devices_online` | Devices powered on; count by type and trusted/untrusted in the attributes |
| `sensor.sentinella_devices_linked_to_the_smart_home` | Network devices already known to an integration; `not_linked` count and integrations in the attributes |
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
| `sensor.sentinella_<network>_devices` | One per smart home network with devices (`zigbee`, `z_wave`, `matter`, `bluetooth`, `mqtt`): total, with all the counts in the attributes |
| `sensor.sentinella_<network>_not_communicating` | Unreachable or silent devices of that network; names in the attributes |
| `sensor.sentinella_<network>_low_batteries` | Devices with a low battery; names and levels in the attributes |
| `sensor.sentinella_<network>_open_findings` | Open findings of that network |
| `binary_sensor.sentinella_<network>_needs_attention` | On if the network has devices not communicating, low batteries or open findings |
| `sensor.sentinella_failed_logins_24h` | Failed login attempts to Home Assistant in the last 24 hours; split local/Internet and source addresses in the attributes |
| `sensor.sentinella_banned_addresses` | Addresses banned by Home Assistant |
| `binary_sensor.sentinella_login_attempts` | On while there are failed login attempts in the last 24 hours |

Entity IDs above are those of an English installation over MQTT; in Italian they derive from the Italian entity name. Attribute keys are always in English and do not change with the language. With the API channel the IDs are fixed: `sensor.sentinella_<id>` (for example `sensor.sentinella_dispositivi_online`, `binary_sensor.sentinella_falle`, `binary_sensor.sentinella_dispositivo_<mac>`).

Only aggregate sensors are published: there is no entity per device. The per-device "Online" sensors created by versions before 0.6.0 are removed automatically at the first start. Attributes list by name only the devices that need action (untrusted, not communicating, low battery).

Every incident also fires the `sentinella_incident` event (fields `type`, `severity`, `title`, `detail`, `device`, `ip`, `network`), handy as a trigger:

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
| `monitor_zigbee`, `monitor_zwave`, `monitor_matter`, `monitor_bluetooth`, `monitor_mqtt` | on | One checkbox per smart home section: turn off the networks you do not have |
| `monitor_access` | on | Access section: failed logins and banned addresses from the Home Assistant log |
| `zigbee2mqtt_in_zigbee` | on | Zigbee2MQTT devices appear under Zigbee (on) or under MQTT (off), never in both |
| `health_interval_minutes` | 30 | Minutes between one smart home and access check and the next |
| `battery_threshold` | 20 | Battery percentage at or below which a device is reported |
| `silent_hours` | 48 | Hours of silence after which a battery-powered device is reported |
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
