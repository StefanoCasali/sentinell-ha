# Sentinella

Controlla la rete di casa dall'interno e ti dice cosa sistemare.

## Cosa controlla

- **Dispositivi**: tutti quelli accesi sulla rete, con MAC e produttore. Dopo la prima scansione ogni dispositivo nuovo viene segnalato finché non lo segni come fidato.
- **Servizi a rischio**: circa 50 porte tipiche (Telnet, FTP, SMB, RDP, VNC, ADB, MQTT, Redis, Docker, database, DVR). Dove ha senso verifica anche se il servizio accetta chiunque: FTP anonimo, MQTT e Redis senza password, VNC senza autenticazione, SMBv1, API Docker aperta, login su HTTP non cifrato.
- **Router**: UPnP attivo, porte aperte verso Internet via UPnP, indirizzo pubblico (o CGNAT), servizi di amministrazione esposti sulla LAN.
- **Verifiche manuali**: una lista di impostazioni del router che nessuna scansione può leggere (WPS, password di amministrazione, port forwarding manuali, DMZ, rete ospiti).

## Cosa sa di ogni dispositivo

Oltre a IP, MAC e produttore, la scheda **Dispositivi** mostra ciò che il dispositivo annuncia da solo in rete:

| Fonte | Cosa fornisce |
|---|---|
| mDNS/Bonjour | Nome "umano", modello, firmware e servizi offerti (Chromecast, AirPlay, stampanti, HomeKit, ESPHome, Shelly...) |
| SSDP/UPnP | Produttore, modello e tipo di TV, console, NAS, media player |
| NetBIOS | Nome del computer e gruppo di lavoro |
| Certificato HTTPS | Intestatario, se è autofirmato, scadenza (un certificato scaduto è segnalato come falla bassa) |
| MAC | Se è casuale ("privato"), tipico di telefoni e tablet |

Da questi dati viene dedotto il **tipo** (router, computer, telefono, TV, audio, stampante, telecamera, NAS, dispositivo smart, hub, console, server): è una stima, serve a filtrare l'elenco e può sbagliare.

Con l'opzione `deep_scan` si aggiunge una scansione nmap delle porte aperte che rileva software e versione dei servizi e stima il sistema operativo. Allunga la scansione di alcuni minuti ed è più visibile ai dispositivi, per questo è spenta di default. Le versioni vengono mostrate, non confrontate con un elenco di vulnerabilità note.

## Collegamento con la domotica

Per ogni dispositivo di rete Sentinella cerca in Home Assistant chi lo conosce già e lo riporta nella scheda, con il collegamento alla pagina del dispositivo, le integrazioni, l'area e le entità. La corrispondenza si cerca per:

- **MAC** nelle connessioni o negli identificativi del dispositivo di Home Assistant;
- **indirizzo di configurazione** del dispositivo (il link "Visita" che punta al suo IP);
- **IP o MAC nelle entità**: attributi `ip`, `ip_address`, `host`, `mac`, `mac_address`, oppure sensori il cui stato è l'indirizzo IP (tipico di ESPHome, Shelly, WLED, dei device tracker).

Un dispositivo "non collegato" è semplicemente in rete senza che nessuna integrazione lo usi: può essere normale (un telefono, una TV) o un indizio da approfondire. Le integrazioni cloud che non conoscono né IP né MAC (per esempio Tuya) non possono essere riconosciute. Via MQTT, l'integrazione `mqtt` può comparire accanto alle altre perché il sensore "In rete" di Sentinella viene agganciato allo stesso dispositivo.

Il registro viene letto a ogni scansione; l'esito è nella scheda **Stato e cronologia**. Si disattiva con l'opzione `ha_links`.

## Falle e incidenti

Una **falla** è uno stato: resta aperta finché la scansione la trova (o finché la ignori). Un **incidente** è un cambiamento sospetto tra due scansioni e resta "da verificare" finché non premi **Ho verificato**:

| Incidente | Quando scatta |
|---|---|
| `nuovo_dispositivo` | Un dispositivo mai visto si collega alla rete |
| `nuovo_servizio` | Un dispositivo noto apre una porta che prima era chiusa |
| `porta_esposta` | Compare una nuova apertura verso Internet sul router |
| `router_cambiato` | Il MAC del router cambia (router sostituito oppure ARP spoofing) |
| `upnp_attivato` | UPnP, prima spento, risulta attivo |
| `nuova_falla` | Compare una falla critica o alta senza che sia cambiata una porta |

La prima scansione fa da riferimento e non genera incidenti. Gli incidenti si vedono solo al passaggio di una scansione: non è un monitoraggio in tempo reale del traffico.

## Cosa può correggere da solo

Solo le aperture UPnP: il pulsante **Chiudi la porta** chiede conferma, invia la richiesta al router e rilegge l'elenco per verificare che l'apertura sia sparita. Per tutto il resto ogni problema ha la sezione **Come rimediare** con i passi da fare a mano.

Il router ZTE H6655P fornito dall'operatore non espone un'API di configurazione: WPS, port forwarding manuali, DMZ e password si cambiano solo dal suo pannello web.

## Entità in Home Assistant

Se è installato un broker MQTT (add-on Mosquitto con l'integrazione MQTT), le entità vengono create via MQTT discovery sotto il dispositivo **Sentinella**: hanno un ID univoco, si possono rinominare e mantengono lo stato ai riavvii. Le credenziali del broker le fornisce il Supervisor, non c'è nulla da configurare.

Senza broker le stesse entità vengono scritte tramite l'API di Home Assistant: funzionano in automazioni e plance, ma non sono modificabili dall'interfaccia e dopo un riavvio di Home Assistant ricompaiono entro 10 minuti.

| Entità | Contenuto |
|---|---|
| `sensor.sentinella_dispositivi_in_rete` | Dispositivi accesi; elenco negli attributi |
| `sensor.sentinella_dispositivi_conosciuti` | Dispositivi visti almeno una volta |
| `sensor.sentinella_dispositivi_collegati_alla_domotica` | Dispositivi in rete già noti a un'integrazione; elenco dei non collegati negli attributi |
| `sensor.sentinella_dispositivi_non_fidati` | Accesi e non ancora classificati; elenco negli attributi |
| `binary_sensor.sentinella_nuovo_dispositivo_rilevato` | Acceso finché c'è un dispositivo nuovo da classificare |
| `sensor.sentinella_ultimo_dispositivo_comparso` | Nome, IP, MAC e data dell'ultimo arrivato |
| `sensor.sentinella_problemi_aperti` | Totale delle falle aperte; elenco e conteggi negli attributi |
| `sensor.sentinella_problemi_critici` / `_alti` / `_medi` / `_bassi` | Conteggio per gravità |
| `sensor.sentinella_gravita_massima` | `critico`, `alto`, `medio`, `basso`, `informativo` o `nessuna` |
| `binary_sensor.sentinella_falle_di_sicurezza` | Acceso se c'è almeno una falla media o superiore |
| `sensor.sentinella_punteggio_di_sicurezza` | Da 0 a 100: scende con falle, incidenti e dispositivi non classificati |
| `binary_sensor.sentinella_incidente_di_sicurezza` | Acceso finché c'è un incidente da verificare |
| `sensor.sentinella_incidenti_da_verificare` | Numero di incidenti; elenco negli attributi |
| `sensor.sentinella_ultimo_incidente` | Titolo, data, gravità e dettaglio |
| `sensor.sentinella_porte_aperte_verso_internet` | Aperture UPnP; elenco negli attributi |
| `binary_sensor.sentinella_upnp_attivo_sul_router` | Stato di UPnP |
| `sensor.sentinella_indirizzo_ip_pubblico` | Indirizzo WAN dichiarato dal router |
| `sensor.sentinella_verifiche_manuali_completate` | Voci spuntate della lista del router; mancanti negli attributi |
| `sensor.sentinella_ultima_scansione`, `_durata_ultima_scansione`, `binary_sensor.sentinella_scansione_in_corso` | Diagnostica |
| `binary_sensor.<dispositivo>_in_rete` | Uno per dispositivo: acceso o spento, con IP, MAC, tipo, modello, sistema operativo, porte aperte, falle e i riferimenti alla domotica (`collegato_a_home_assistant`, `dispositivi_ha`, `integrazioni_ha`, `entita_ha`) |

Con il canale API i nomi sono `sensor.sentinella_<id>` (per esempio `sensor.sentinella_dispositivi_online`, `binary_sensor.sentinella_falle`, `binary_sensor.sentinella_dispositivo_<mac>`).

Via MQTT i sensori dei singoli dispositivi vengono agganciati, tramite il MAC, al dispositivo già presente in Home Assistant se un'altra integrazione lo conosce. Si disattivano con l'opzione `device_entities`.

A ogni incidente viene anche emesso l'evento `sentinella_incidente` (campi `tipo`, `gravita`, `titolo`, `dettaglio`, `dispositivo`, `ip`), utile come trigger:

```yaml
automation:
  - alias: Avviso incidente di rete
    trigger:
      - platform: event
        event_type: sentinella_incidente
    action:
      - service: notify.notify
        data:
          title: "Sentinella: {{ trigger.event.data.titolo }}"
          message: "{{ trigger.event.data.dettaglio }}"
```

## Limiti da conoscere

- La scansione parte **dall'interno**: vede cosa è esposto sulla LAN, non cosa è raggiungibile da Internet. Le aperture verso l'esterno si conoscono solo via UPnP e dalla verifica manuale dei port forwarding.
- Vede solo la rete a cui è collegato Home Assistant. Una rete ospiti isolata o una VLAN separata non sono raggiungibili.
- Non prova password di fabbrica e non sfrutta vulnerabilità: le verifiche sono una singola connessione in sola lettura.
- I dispositivi con MAC casuale (telefoni) possono ricomparire come nuovi quando cambiano indirizzo: disattiva il MAC privato per la rete di casa oppure segnali di nuovo come fidati.

## Opzioni

| Opzione | Predefinito | Significato |
|---|---|---|
| `scan_interval_hours` | 6 | Ore tra una scansione automatica e la successiva |
| `networks` | vuoto | Reti da controllare (es. `192.168.1.0/24`). Vuoto: la rete dell'host |
| `extra_ports` | vuoto | Porte in più da controllare |
| `active_probes` | attivo | Verifica se i servizi accettano accessi senza password |
| `notify` | attivo | Notifica in Home Assistant a ogni incidente |
| `device_entities` | attivo | Crea un sensore "In rete" per ogni dispositivo |
| `ha_links` | attivo | Cerca in Home Assistant i dispositivi e le entità già collegati |
| `deep_scan` | spento | Versioni dei servizi e sistema operativo con nmap (più lenta) |
| `mqtt_host`, `mqtt_port`, `mqtt_username`, `mqtt_password` | vuoto | Solo per un broker diverso dall'add-on Mosquitto |

Scrivi le reti con la maschera (`192.168.1.0/24`); senza maschera viene assunto `/24`.

## Se i sensori non compaiono

Apri la scheda **Stato e cronologia** del pannello: la prima scheda dice quale canale è in uso (MQTT, API o nessuno), quante entità sono state pubblicate e, se MQTT non è utilizzabile, perché. La stessa informazione è nel log dell'add-on, nella riga `Sensori verso Home Assistant`.

- **Canale MQTT**: le entità sono sotto Impostazioni > Dispositivi e servizi > MQTT, dispositivo "Sentinella".
- **Canale API**: non c'è un dispositivo; cerca `sentinella` in Strumenti per sviluppatori > Stati.
- Per passare a MQTT serve l'add-on Mosquitto avviato con l'integrazione MQTT configurata, oppure le opzioni `mqtt_*` per un altro broker.

## Prima scansione

Alla prima scansione tutti i dispositivi risultano "da classificare" senza generare avvisi. Scorri la scheda **Dispositivi**, dai un nome a quelli che riconosci e segnali come fidati: da quel momento ogni nuovo arrivo viene notificato.
