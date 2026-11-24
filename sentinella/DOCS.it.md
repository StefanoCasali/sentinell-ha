# Sentinella

[English](DOCS.md)

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

Il registro viene letto a ogni scansione; l'esito è nella scheda **Stato**. Si disattiva con l'opzione `ha_links`.

## Reti della domotica

Oltre alla rete locale, Sentinella analizza le reti della domotica. Ognuna è una sezione separata del pannello: **Zigbee** (ZHA, Zigbee2MQTT, deCONZ), **Z-Wave** (Z-Wave JS), **Matter**, **Bluetooth** e **MQTT**. I dispositivi non vengono interrogati direttamente: Sentinella legge ciò che Home Assistant conosce già (dispositivi, entità e il loro stato), quindi non serve installare altro. Una sezione resta vuota finché Home Assistant non ha almeno un dispositivo di quel tipo.

Ogni sezione ha la sua casella nelle opzioni dell'add-on (`monitor_zigbee`, `monitor_zwave`, `monitor_matter`, `monitor_bluetooth`, `monitor_mqtt`): spegni quelle che non usi. Una sezione spenta sparisce dal pannello, i suoi problemi aperti vengono chiusi, i suoi incidenti segnati come verificati e i suoi sensori rimossi da Home Assistant.

Un dispositivo appartiene a una sola sezione, quindi niente viene segnalato due volte. I dispositivi Zigbee2MQTT tecnicamente arrivano a Home Assistant via MQTT: con `zigbee2mqtt_in_zigbee` attiva (il default) compaiono sotto Zigbee e la sezione MQTT contiene solo ciò che non arriva da Zigbee2MQTT; con l'opzione spenta vengono contati sotto MQTT. La stessa regola vale per i dispositivi Z-Wave portati su MQTT da Z-Wave JS UI.

Ogni 30 minuti (opzione `health_interval_minutes`), indipendentemente dalla scansione di rete, controlla:

| Controllo | Quando viene segnalato |
|---|---|
| Dispositivo non raggiungibile | Tutte le sue entità sono non disponibili, oppure il nodo Z-Wave è segnato come dead |
| Il coordinatore non risponde | Il bridge o il coordinatore è non disponibile (gravità alta: tutta la rete è ferma) |
| Dispositivo che non comunica più | Un dispositivo a batteria non invia nulla da `silent_hours` (48 di default) |
| Batteria in esaurimento | Batteria pari o inferiore a `battery_threshold` (20% di default), oppure segnalazione di batteria scarica del dispositivo |
| Segnale debole | Qualità del collegamento Zigbee sotto 25, oppure segnale sotto -88 dBm |
| Aggiornamento firmware disponibile | Home Assistant propone un aggiornamento per il dispositivo |
| Accoppiamento Zigbee lasciato aperto | Zigbee2MQTT sta ancora accettando nuovi dispositivi |

I cambiamenti tra un controllo e il successivo diventano incidenti: `new_device` (compare un dispositivo in una rete), `device_offline` (un dispositivo smette di rispondere), `network_outage` (gran parte di una rete cade insieme), `battery_drop` (30 punti o più persi dall'ultimo controllo) e `device_removed`.

Da sapere:

- "Non comunica più" si valuta solo sui dispositivi a batteria: una presa a rete che nessuno usa può tacere per giorni senza che ci sia nulla di rotto.
- Dopo un riavvio di Home Assistant i tempi di "ultima comunicazione" ripartono dal riavvio.
- Qualità del collegamento e segnale si controllano solo se il sensore corrispondente è attivo in Home Assistant (Zigbee2MQTT disattiva `linkquality` di default).
- I dispositivi di altre integrazioni (Wi-Fi, cloud) non fanno parte di nessuna sezione; compaiono nella rete locale se hanno un indirizzo IP.

## Accessi a Home Assistant

La sezione **Accessi** tiene d'occhio chi prova a entrare in Home Assistant. A ogni controllo Sentinella legge il log di Home Assistant tramite il Supervisor e cerca le richieste con credenziali non valide e gli indirizzi che Home Assistant ha bloccato.

- Ogni indirizzo di provenienza con tentativi falliti diventa un incidente `failed_login`: gravità alta se arriva da Internet o se i tentativi sono 5 o più, media negli altri casi. Un indirizzo locale viene associato al dispositivo trovato dalla scansione di rete, quando è noto.
- Un indirizzo bloccato da Home Assistant diventa un incidente `ip_banned`.
- Finché ci sono tentativi falliti nelle ultime 24 ore resta aperto un problema, con i passi per proteggere l'accesso (autenticazione a più fattori, `ip_ban_enabled`, nessuna esposizione diretta della porta 8123).
- Se l'URL esterno configurato in Home Assistant usa HTTP in chiaro, viene segnalato un problema di gravità alta.

Da sapere:

- Serve il permesso dell'add-on di leggere il log di Home Assistant (`hassio_role: homeassistant`); Home Assistant lo mostra all'aggiornamento. Il controllo si disattiva con l'opzione `monitor_access`.
- Si vede solo ciò che è ancora nel log al momento del controllo: su un'installazione che scrive molto, le righe vecchie possono scorrere via tra un controllo e l'altro.
- Gli accessi riusciti non vengono scritti nel log, quindi non possono essere segnalati.
- Dietro un reverse proxy senza `use_x_forwarded_for` e `trusted_proxies`, ogni tentativo sembra arrivare dal proxy.


## Falle e incidenti

Una **falla** è uno stato: resta aperta finché la scansione la trova (o finché la ignori). Un **incidente** è un cambiamento sospetto tra due scansioni e resta "da verificare" finché non premi **Ho verificato**:

| Incidente | Quando scatta |
|---|---|
| `new_device` | Un dispositivo mai visto si collega alla rete |
| `new_service` | Un dispositivo noto apre una porta che prima era chiusa |
| `exposed_port` | Compare una nuova apertura verso Internet sul router |
| `router_changed` | Il MAC del router cambia (router sostituito oppure ARP spoofing) |
| `upnp_enabled` | UPnP, prima spento, risulta attivo |
| `new_vulnerability` | Compare una falla critica o alta senza che sia cambiata una porta |

La prima scansione fa da riferimento e non genera incidenti. Gli incidenti si vedono solo al passaggio di una scansione: non è un monitoraggio in tempo reale del traffico.

## Cosa può correggere da solo

Solo le aperture UPnP: il pulsante **Chiudi la porta** chiede conferma, invia la richiesta al router e rilegge l'elenco per verificare che l'apertura sia sparita. Per tutto il resto ogni problema ha la sezione **Come rimediare** con i passi da fare a mano.

Il router ZTE H6655P fornito dall'operatore non espone un'API di configurazione: WPS, port forwarding manuali, DMZ e password si cambiano solo dal suo pannello web.

## Entità in Home Assistant

Se è installato un broker MQTT (add-on Mosquitto con l'integrazione MQTT), le entità vengono create via MQTT discovery sotto il dispositivo **Sentinella**: hanno un ID univoco, si possono rinominare e mantengono lo stato ai riavvii. Le credenziali del broker le fornisce il Supervisor, non c'è nulla da configurare.

Senza broker le stesse entità vengono scritte tramite l'API di Home Assistant: funzionano in automazioni e plance, ma non sono modificabili dall'interfaccia e dopo un riavvio di Home Assistant ricompaiono entro 10 minuti.

| Entità | Contenuto |
|---|---|
| `sensor.sentinella_dispositivi_in_rete` | Dispositivi accesi; conteggio per tipo e fidati/non fidati negli attributi |
| `sensor.sentinella_dispositivi_conosciuti` | Dispositivi visti almeno una volta |
| `sensor.sentinella_dispositivi_collegati_alla_domotica` | Dispositivi in rete già noti a un'integrazione; conteggio dei non collegati e integrazioni negli attributi |
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
| `sensor.sentinella_<rete>_dispositivi` | Uno per ogni rete della domotica con dispositivi (`zigbee`, `z_wave`, `matter`, `bluetooth`, `mqtt`): totale, con tutti i conteggi negli attributi |
| `sensor.sentinella_<rete>_non_comunicano` | Dispositivi non raggiungibili o silenziosi di quella rete; nomi negli attributi |
| `sensor.sentinella_<rete>_batterie_scariche` | Dispositivi con batteria scarica; nomi e livelli negli attributi |
| `sensor.sentinella_<rete>_problemi_aperti` | Problemi aperti di quella rete |
| `binary_sensor.sentinella_<rete>_richiede_attenzione` | Acceso se la rete ha dispositivi che non comunicano, batterie scariche o problemi aperti |
| `sensor.sentinella_accessi_falliti_24_ore` | Tentativi di accesso falliti a Home Assistant nelle ultime 24 ore; suddivisione locale/Internet e indirizzi di provenienza negli attributi |
| `sensor.sentinella_indirizzi_bloccati` | Indirizzi bloccati da Home Assistant |
| `binary_sensor.sentinella_tentativi_di_accesso` | Acceso finché ci sono tentativi di accesso falliti nelle ultime 24 ore |

I nomi qui sopra valgono per un'installazione in italiano via MQTT; in inglese derivano dal nome inglese dell'entità. Le chiavi degli attributi sono sempre in inglese e non cambiano con la lingua. Con il canale API i nomi sono `sensor.sentinella_<id>` (per esempio `sensor.sentinella_dispositivi_online`, `binary_sensor.sentinella_falle`, `binary_sensor.sentinella_dispositivo_<mac>`).

Vengono pubblicati solo sensori aggregati: non c'è un'entità per dispositivo. I sensori "In rete" dei singoli dispositivi creati dalle versioni precedenti alla 0.6.0 vengono rimossi in automatico al primo avvio. Negli attributi compaiono per nome solo i dispositivi su cui serve intervenire (non fidati, che non comunicano, con batteria scarica).

A ogni incidente viene anche emesso l'evento `sentinella_incident` (campi `type`, `severity`, `title`, `detail`, `device`, `ip`, `network`), utile come trigger:

```yaml
automation:
  - alias: Avviso incidente di rete
    trigger:
      - platform: event
        event_type: sentinella_incident
    action:
      - service: notify.notify
        data:
          title: "Sentinella: {{ trigger.event.data.title }}"
          message: "{{ trigger.event.data.detail }}"
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
| `monitor_zigbee`, `monitor_zwave`, `monitor_matter`, `monitor_bluetooth`, `monitor_mqtt` | attive | Una casella per ogni sezione della domotica: spegni le reti che non hai |
| `monitor_access` | attiva | Sezione Accessi: accessi falliti e indirizzi bloccati dal log di Home Assistant |
| `zigbee2mqtt_in_zigbee` | attiva | I dispositivi Zigbee2MQTT compaiono sotto Zigbee (attiva) o sotto MQTT (spenta), mai in entrambe |
| `health_interval_minutes` | 30 | Minuti tra un controllo di domotica e accessi e il successivo |
| `battery_threshold` | 20 | Percentuale di batteria al di sotto della quale un dispositivo viene segnalato |
| `silent_hours` | 48 | Ore di silenzio dopo le quali un dispositivo a batteria viene segnalato |
| `ha_links` | attivo | Cerca in Home Assistant i dispositivi e le entità già collegati |
| `deep_scan` | spento | Versioni dei servizi e sistema operativo con nmap (più lenta) |
| `language` | `auto` | Lingua di pannello, falle, incidenti e nomi delle entità: `auto` segue Home Assistant (italiano o inglese) |
| `mqtt_host`, `mqtt_port`, `mqtt_username`, `mqtt_password` | vuoto | Solo per un broker diverso dall'add-on Mosquitto |

Scrivi le reti con la maschera (`192.168.1.0/24`); senza maschera viene assunto `/24`.

## Se i sensori non compaiono

Apri la scheda **Stato** del pannello: la prima scheda dice quale canale è in uso (MQTT, API o nessuno), quante entità sono state pubblicate e, se MQTT non è utilizzabile, perché. La stessa informazione è nel log dell'add-on, nella riga `Sensors to Home Assistant`.

- **Canale MQTT**: le entità sono sotto Impostazioni > Dispositivi e servizi > MQTT, dispositivo "Sentinella".
- **Canale API**: non c'è un dispositivo; cerca `sentinella` in Strumenti per sviluppatori > Stati.
- Per passare a MQTT serve l'add-on Mosquitto avviato con l'integrazione MQTT configurata, oppure le opzioni `mqtt_*` per un altro broker.

## Prima scansione

Alla prima scansione tutti i dispositivi risultano "da classificare" senza generare avvisi. Scorri la scheda **Dispositivi**, dai un nome a quelli che riconosci e segnali come fidati: da quel momento ogni nuovo arrivo viene notificato.
