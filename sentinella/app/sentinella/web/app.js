"use strict";

// Tutto il testo passa da textContent: nomi host e banner arrivano da dispositivi non fidati.
function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === false || v == null) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "checked" || k === "disabled" || k === "open") el[k] = !!v;
    else el.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

// Lingua dell'interfaccia: la decide il backend (opzione dell'add-on o lingua di Home Assistant).
let LANG = "en";
const T = (it, en) => (LANG === "it" ? it : en);
const sevLabel = (s) => ({
  critical: T("Critico", "Critical"), high: T("Alto", "High"), medium: T("Medio", "Medium"),
  low: T("Basso", "Low"), info: "Info",
}[s] || s);
const $ = (id) => document.getElementById(id);
const fmt = (ts) => ts
  ? new Date(ts * 1000).toLocaleString(LANG === "it" ? "it-IT" : undefined, { dateStyle: "short", timeStyle: "short" })
  : "-";

let state = null;
let lastJson = "";
let tab = "findings";
let showClosed = false;
const openDetails = new Set();

async function api(path, body) {
  const opts = body === undefined ? {} : {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Sentinella": "1" },
    body: JSON.stringify(body),
  };
  const res = await fetch(path, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || T(`Errore ${res.status}`, `Error ${res.status}`));
  return data;
}

function banner(text, kind) {
  const el = $("banner");
  el.hidden = !text;
  el.textContent = text || "";
  el.className = "banner " + (kind || "");
}

async function act(path, body, okText) {
  try {
    const res = await api(path, body);
    banner(res.message || okText || "", res.message || okText ? "ok" : "");
  } catch (err) {
    banner(err.message, "error");
  }
  await refresh(true);
}

function confirmDialog(title, text) {
  return new Promise((resolve) => {
    const dlg = $("confirm");
    $("confirm-title").textContent = title;
    $("confirm-text").textContent = text;
    const done = (value) => { dlg.close(); resolve(value); };
    $("confirm-yes").onclick = () => done(true);
    $("confirm-no").onclick = () => done(false);
    dlg.oncancel = () => resolve(false);
    dlg.showModal();
  });
}

function deviceLabel(d) {
  const info = (d && d.info) || {};
  return d ? (d.name || info.friendly_name || d.hostname || info.model || d.vendor || d.ip) : "";
}

function applyStaticTexts() {
  document.documentElement.lang = LANG;
  const tabs = {
    findings: T("Problemi", "Findings"), incidents: T("Incidenti", "Incidents"),
    devices: T("Dispositivi", "Devices"), router: "Router",
    history: T("Stato e cronologia", "Status and history"),
  };
  document.querySelectorAll(".tabs button").forEach((b) => { b.textContent = tabs[b.dataset.tab]; });
  $("confirm-no").textContent = T("Annulla", "Cancel");
  $("confirm-yes").textContent = T("Conferma", "Confirm");
}

// ---------------------------------------------------------------- riepilogo

function renderSummary() {
  const c = state.counts;
  const online = state.devices.filter((d) => d.online);
  const pending = state.incidents.filter((i) => !i.acknowledged).length;
  const tiles = [
    [state.score, T("Punteggio su 100", "Score out of 100"), state.score >= 80 ? "okc" : state.score >= 50 ? "medium" : "high"],
    [pending, T("Incidenti da verificare", "Incidents to review"), pending ? "high" : "okc"],
    [c.critical + c.high, T("Critici e alti", "Critical and high"), c.critical + c.high ? "high" : "okc"],
    [c.medium, T("Medi", "Medium"), c.medium ? "medium" : "okc"],
    [c.low + c.info, T("Bassi e informativi", "Low and info"), "info"],
    [online.length, T("Dispositivi accesi", "Devices online"), "info"],
    [online.filter((d) => !d.trusted).length, T("Da classificare", "To classify"), "info"],
  ];
  $("summary").replaceChildren(...tiles.map(([n, label, cls]) =>
    h("div", { class: "tile " + cls }, h("b", {}, n), h("span", {}, label))));

  const last = state.scans[state.scans.length - 1];
  const s = state.status;
  $("scan").disabled = s.running;
  $("scan").textContent = s.running
    ? (s.phase || T("Scansione in corso", "Scan in progress")) + "..." : T("Avvia scansione", "Start scan");
  const nets = state.networks.join(", ") || T("rete locale", "local network");
  $("subtitle").textContent = last
    ? T(`Ultima scansione: ${fmt(last.ts)} su ${nets}`, `Last scan: ${fmt(last.ts)} on ${nets}`) +
      (s.next_scan ? T(` - prossima: ${fmt(s.next_scan)}`, ` - next: ${fmt(s.next_scan)}`) : "")
    : T("Nessuna scansione ancora eseguita", "No scan has run yet");
  if (s.error) banner(T("Ultima scansione non riuscita: ", "Last scan failed: ") + s.error, "error");
}

// ---------------------------------------------------------------- problemi

function findingCard(f) {
  const dev = state.devices.find((d) => d.key === f.device_key);
  const portText = f.port && f.category !== "router" ? T(" - porta ", " - port ") + f.port : "";
  const where = dev ? `${deviceLabel(dev)} (${dev.ip})${portText}`
    : (f.category === "router" ? "Router" : f.ip || "");
  const closed = f.status !== "open";
  const buttons = [];
  if (f.status === "open") {
    if (f.action) {
      buttons.push(h("button", { class: "danger small", onclick: async () => {
        const port = `${f.action.external_port}/${f.action.protocol}`;
        const ok = await confirmDialog(f.action.label + "?", T(
          `Verrà chiesto al router di chiudere la porta ${port}. Il servizio che la usa non sarà più raggiungibile da Internet.`,
          `The router will be asked to close port ${port}. The service using it will no longer be reachable from the Internet.`));
        if (ok) act("api/action", { id: f.id, confirm: true });
      } }, f.action.label));
    }
    if (f.id.startsWith("new-device:")) {
      buttons.push(h("button", { class: "small", onclick: () => act("api/device", { key: f.device_key, trusted: true }) },
        T("Lo riconosco: fidato", "I recognise it: trusted")));
    }
    buttons.push(h("button", { class: "small", onclick: () => act("api/finding", { id: f.id, status: "ignored" }) },
      T("Ignora", "Ignore")));
  } else if (f.status === "ignored") {
    buttons.push(h("button", { class: "small", onclick: () => act("api/finding", { id: f.id, status: "open" }) },
      T("Riapri", "Reopen")));
  }
  const details = h("details", { open: openDetails.has(f.id) },
    h("summary", {}, T("Come rimediare", "How to fix")),
    h("ol", { class: "steps" }, f.remediation.map((step) => h("li", {}, step))));
  details.addEventListener("toggle", () => details.open ? openDetails.add(f.id) : openDetails.delete(f.id));
  return h("div", { class: `card sev ${closed ? "info" : f.severity}` },
    h("div", { class: "row" },
      h("span", { class: "badge " + f.severity }, sevLabel(f.severity)),
      h("h3", { class: "grow" }, f.title),
      closed ? h("span", { class: "badge" }, f.status === "ignored" ? T("Ignorato", "Ignored") : T("Risolto", "Resolved")) : null),
    h("div", { class: "muted" }, where + T(" - rilevato il ", " - detected on ") + fmt(f.first_seen)),
    h("p", {}, f.detail),
    details,
    buttons.length ? h("div", { class: "actions" }, buttons) : null);
}

function renderFindings() {
  const open = state.findings.filter((f) => f.status === "open");
  const closed = state.findings.filter((f) => f.status !== "open");
  const out = [h("label", { class: "filter" },
    h("span", {}, h("input", { type: "checkbox", checked: showClosed,
      onchange: (e) => { showClosed = e.target.checked; render(); } }),
      T(` Mostra anche ignorati e risolti (${closed.length})`, ` Also show ignored and resolved (${closed.length})`)))];
  if (!open.length) {
    out.push(h("div", { class: "card empty" }, state.scans.length
      ? T("Nessun problema aperto. Controlla anche la scheda Router per le verifiche manuali.",
          "No open findings. Also check the Router tab for the manual checks.")
      : T("Avvia la prima scansione per controllare la rete.", "Start the first scan to check the network.")));
  }
  out.push(...open.map(findingCard));
  if (showClosed) out.push(...closed.map(findingCard));
  return out;
}

// ---------------------------------------------------------------- incidenti

function renderIncidents() {
  if (!state.incidents.length) {
    return [h("div", { class: "card empty" }, T(
      "Nessun incidente. Qui compaiono i cambiamenti sospetti tra una scansione e l'altra: nuovi dispositivi, nuove porte, nuove aperture verso Internet.",
      "No incidents. Suspicious changes between one scan and the next appear here: new devices, new ports, new forwards to the Internet."))];
  }
  const pending = state.incidents.filter((i) => !i.acknowledged);
  const out = [];
  if (pending.length > 1) {
    out.push(h("div", { class: "actions filter" },
      h("button", { class: "small", onclick: () => act("api/incident", { all: true }) },
        T(`Segna tutti come verificati (${pending.length})`, `Mark all as reviewed (${pending.length})`))));
  }
  out.push(...state.incidents.map((i) => h("div", { class: `card sev ${i.acknowledged ? "info" : i.severity}` },
    h("div", { class: "row" },
      h("span", { class: "badge " + i.severity }, sevLabel(i.severity)),
      h("h3", { class: "grow" }, i.title),
      i.acknowledged ? h("span", { class: "badge" }, T("Verificato", "Reviewed")) : null),
    h("div", { class: "muted" }, fmt(i.ts) + (i.device ? ` - ${i.device}${i.ip ? " (" + i.ip + ")" : ""}` : "")),
    h("p", {}, i.detail),
    i.acknowledged ? null : h("div", { class: "actions" },
      h("button", { class: "small", onclick: () => act("api/incident", { id: i.id }) }, T("Ho verificato", "I have reviewed it"))))));
  return out;
}

// ---------------------------------------------------------------- dispositivi

function haLinks(d) {
  const link = d.ha;
  if (!link) return null;
  if (!link.linked) {
    return h("div", { class: "halink muted" }, T(
      "Domotica: non collegato a nessuna integrazione di Home Assistant.",
      "Smart home: not linked to any Home Assistant integration."));
  }
  const rows = link.devices.map((x) => h("div", {},
    h("b", {}, T("In Home Assistant: ", "In Home Assistant: ")),
    // Il pannello è in un iframe: il collegamento apre la pagina del dispositivo nella finestra principale.
    h("a", { href: "/config/devices/device/" + encodeURIComponent(x.id), target: "_top" }, x.name || x.id),
    [x.manufacturer, x.model].filter(Boolean).length ? ` (${[x.manufacturer, x.model].filter(Boolean).join(" ")})` : "",
    x.integrations.length ? T(" - integrazioni: ", " - integrations: ") + x.integrations.join(", ") : "",
    x.area ? T(" - area: ", " - area: ") + x.area : "",
    h("span", { class: "muted" }, T(" - riconosciuto per ", " - matched by ") + x.match.join(", ")),
    x.entity_count ? h("details", {},
      h("summary", {}, T(`${x.entity_count} entità`, `${x.entity_count} entities`)),
      h("div", { class: "ports" }, x.entities.map((e) => h("span", { class: "port" }, e)),
        x.entity_count > x.entities.length ? h("span", { class: "muted" }, "...") : null)) : null));
  if (link.entities.length) {
    rows.push(h("div", {}, h("b", {}, T("Entità che lo citano: ", "Entities that mention it: ")),
      h("span", { class: "ports" }, link.entities.map((e) =>
        h("span", { class: "port", title: `${e.name} - ${e.match}` }, e.entity_id)))));
  }
  return h("div", { class: "halink" }, rows);
}

function deviceCard(d) {
  const nameInput = h("input", { type: "text", value: d.name || "",
    placeholder: T("Dai un nome (es. TV salotto)", "Give it a name (e.g. Living room TV)"),
    "aria-label": T("Nome del dispositivo", "Device name") });
  nameInput.addEventListener("change", () => act("api/device", { key: d.key, name: nameInput.value }));
  const info = d.info || {};
  const tags = [
    info.type_label && !d.is_gateway ? h("span", { class: "badge low" }, info.type_label) : null,
    d.is_gateway ? h("span", { class: "badge" }, "Router") : null,
    d.is_self ? h("span", { class: "badge" }, T("Questo host", "This host")) : null,
    d.online ? null : h("span", { class: "badge" }, T("Spento", "Offline")),
    d.trusted ? h("span", { class: "badge okc" }, T("Fidato", "Trusted"))
      : h("span", { class: "badge medium" }, T("Da classificare", "To classify")),
  ];
  const problems = state.findings.filter((f) => f.device_key === d.key && f.status === "open").length;
  const facts = [
    [T("Modello", "Model"), [info.manufacturer, info.model].filter(Boolean).join(" ")],
    [T("Nome annunciato", "Announced name"), info.friendly_name],
    [T("Sistema operativo", "Operating system"),
      info.os ? `${info.os} (${T("stima", "estimate")} ${info.os_accuracy || "?"}%)` : ""],
    ["Firmware", info.firmware],
    [T("Nome Windows", "Windows name"), [info.netbios, info.workgroup].filter(Boolean).join(T(" - gruppo ", " - workgroup "))],
    [T("Servizi annunciati", "Announced services"), (info.services || []).join(", ")],
    ["MAC", info.private_mac ? T(
      "casuale (privato): può cambiare e far ricomparire il dispositivo come nuovo",
      "random (private): it can change and make the device show up as new again") : ""],
    [T("Fonti", "Sources"), (info.sources || []).join(", ")],
  ].filter(([, v]) => v);
  return h("div", { class: "card" },
    h("div", { class: "row" },
      h("h3", { class: "grow" }, deviceLabel(d)), tags),
    h("div", { class: "muted" },
      [d.ip, d.mac, d.vendor, d.hostname].filter(Boolean).join(" - ") +
      T(" - visto la prima volta il ", " - first seen on ") + fmt(d.first_seen) +
      (problems ? T(` - ${problems} problemi aperti`, ` - ${problems} open findings`) : "")),
    facts.length ? h("div", { class: "facts" }, facts.map(([k, v]) =>
      h("div", {}, h("span", { class: "muted" }, k + ": "), v))) : null,
    haLinks(d),
    d.ports && d.ports.length ? h("div", { class: "ports" }, d.ports.map((p) => {
      const cert = p.info.cert_subject
        ? ` | ${T("certificato", "certificate")}: ${p.info.cert_subject}${p.info.cert_self_signed ? T(" (autofirmato)", " (self-signed)") : ""}` +
          (p.info.cert_expires ? T(", scade il ", ", expires on ") + fmt(p.info.cert_expires) : "") : "";
      const extra = [p.info.product, p.info.title || p.info.server || p.info.banner].filter(Boolean).join(" | ") + cert;
      return h("span", { class: "port" + (p.info.cert_expired ? " expired" : ""), title: extra },
        `${p.port} ${p.service}${p.info.product ? " · " + p.info.product : ""}`);
    })) : h("div", { class: "muted" }, T("Nessuna porta aperta tra quelle controllate.", "No open port among those checked.")),
    h("div", { class: "actions" },
      nameInput,
      h("button", { class: "small", onclick: () => act("api/device", { key: d.key, trusted: !d.trusted }) },
        d.trusted ? T("Togli da fidati", "Remove from trusted") : T("Segna come fidato", "Mark as trusted")),
      d.online ? null : h("button", { class: "small", onclick: async () => {
        if (await confirmDialog(T("Dimenticare il dispositivo?", "Forget this device?"), T(
          "Verrà rimosso dall'elenco insieme ai suoi problemi. Se si ricollega, sarà segnalato come nuovo.",
          "It will be removed from the list together with its findings. If it reconnects, it will be reported as new.")))
          act("api/device/forget", { key: d.key });
      } }, T("Dimentica", "Forget"))));
}

let typeFilter = "";
let haFilter = "";

function renderDevices() {
  if (!state.devices.length) {
    return [h("div", { class: "card empty" }, T("Nessun dispositivo: avvia una scansione.", "No devices: start a scan."))];
  }
  const typeOf = (d) => (d.info && d.info.type) || "sconosciuto";
  const present = [...new Set(state.devices.map(typeOf))].sort();
  const select = (value, options, onchange, label) => {
    const el = h("select", { "aria-label": label, onchange: (e) => { onchange(e.target.value); render(); } },
      options.map(([v, text]) => h("option", { value: v }, text)));
    el.value = value;
    return el;
  };
  const shown = state.devices.filter((d) =>
    (!typeFilter || typeOf(d) === typeFilter) &&
    (!haFilter || (haFilter === "si") === !!(d.ha && d.ha.linked)));
  return [
    h("div", { class: "filter" },
      select(typeFilter, [["", T("Tutti i tipi", "All types")], ...present.map((t) => [t, (state.types || {})[t] || t])],
        (v) => { typeFilter = v; }, T("Filtra per tipo", "Filter by type")),
      select(haFilter, [["", T("Domotica: tutti", "Smart home: all")],
        ["si", T("Collegati a Home Assistant", "Linked to Home Assistant")], ["no", T("Non collegati", "Not linked")]],
        (v) => { haFilter = v; }, T("Filtra per collegamento alla domotica", "Filter by smart home link")),
      h("span", {}, T(`${shown.length} di ${state.devices.length} dispositivi`, `${shown.length} of ${state.devices.length} devices`))),
    ...shown.map(deviceCard),
  ];
}

// ---------------------------------------------------------------- router

function renderRouter() {
  const r = state.router || {};
  const out = [];
  const facts = [
    [T("Indirizzo del router", "Router address"), r.gateway || T("non rilevato", "not detected")],
    [T("Modello dichiarato", "Declared model"), r.model || "-"],
    ["UPnP", r.available ? T("attivo", "enabled") : T("non rilevato (spento o non supportato)", "not detected (off or unsupported)")],
    [T("Indirizzo pubblico (WAN)", "Public address (WAN)"), r.external_ip || "-"],
  ];
  out.push(h("div", { class: "card" },
    h("h2", {}, T("Stato rilevato", "Detected status")),
    h("div", { class: "table-wrap" }, h("table", {}, h("tbody", {},
      facts.map(([k, v]) => h("tr", {}, h("th", {}, k), h("td", {}, v))))))));

  const maps = r.mappings || [];
  out.push(h("div", { class: "card" },
    h("h2", {}, T("Porte aperte verso Internet via UPnP", "Ports open to the Internet via UPnP")),
    maps.length ? h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, [T("Porta esterna", "External port"), T("Verso", "To"), T("Descrizione", "Description")]
        .map((t) => h("th", {}, t)))),
      h("tbody", {}, maps.map((m) => {
        const dev = state.devices.find((d) => d.ip === m.internal_client);
        return h("tr", {},
          h("td", {}, `${m.external_port}/${m.protocol}`),
          h("td", {}, `${dev ? deviceLabel(dev) + " - " : ""}${m.internal_client}:${m.internal_port}`),
          h("td", {}, m.description || "-"));
      }))))
      : h("p", { class: "muted" }, r.available ? T("Nessuna apertura attiva.", "No active forwards.")
        : T("UPnP non risponde: nessuna apertura leggibile da qui.", "UPnP does not answer: no forward can be read from here.")),
    h("p", { class: "muted" }, T(
      "Qui compaiono solo le aperture create via UPnP. I port forwarding inseriti a mano si vedono solo nel pannello del router: usa la lista qui sotto. Per chiudere un'apertura UPnP usa il pulsante nella scheda Problemi.",
      "Only forwards created through UPnP appear here. Manually configured port forwards are visible only in the router's panel: use the list below. To close a UPnP forward use the button in the Findings tab."))));

  const done = state.checklist.filter((i) => i.done).length;
  const panel = r.gateway ? ` (http://${r.gateway})` : "";
  out.push(h("div", { class: "card" },
    h("h2", {}, T("Verifiche manuali sul router", "Manual router checks") + ` (${done}/${state.checklist.length})`),
    h("p", { class: "muted" }, T(
      `Queste impostazioni non sono leggibili dalla rete: aprile dal pannello del router${panel} e spunta ciò che hai verificato. I nomi dei menu possono variare con il firmware dell'operatore.`,
      `These settings cannot be read from the network: open them in the router's panel${panel} and tick what you have verified. Menu names may vary with your ISP's firmware.`)),
    state.checklist.map((item) => h("div", { class: "card check" },
      h("input", { type: "checkbox", checked: item.done, id: "chk-" + item.id,
        onchange: (e) => act("api/checklist", { id: item.id, done: e.target.checked }) }),
      h("div", {},
        h("label", { for: "chk-" + item.id }, h("b", {}, item.title)),
        h("div", { class: "muted" }, item.why),
        h("div", {}, item.how))))));
  return out;
}

// ---------------------------------------------------------------- stato e cronologia

function haCard() {
  const ha = state.ha || {};
  const channels = { mqtt: "MQTT", api: T("API di Home Assistant", "Home Assistant API"), none: T("Nessuno", "None") };
  const facts = [
    [T("Canale", "Channel"), channels[ha.channel] || ha.channel || "-"],
    [T("Dettaglio", "Detail"), ha.detail || "-"],
    [T("Entità pubblicate", "Published entities"), ha.entities || 0],
    [T("Ultimo invio riuscito", "Last successful publish"), fmt(ha.last_ok)],
  ];
  if (ha.error) facts.push([T("Errore", "Error"), ha.error]);
  if (ha.channel !== "mqtt" && ha.mqtt_reason) facts.push([T("Perché non MQTT", "Why not MQTT"), ha.mqtt_reason]);
  const links = ha.links || {};
  facts.push([T("Registro della domotica", "Smart home registry"), links.ok
    ? T(`letto, ${links.devices} dispositivi di Home Assistant`, `read, ${links.devices} Home Assistant devices`)
    : (links.error || T("non ancora letto", "not read yet"))]);
  return h("div", { class: "card sev " + (ha.error || ha.channel === "none" ? "high" : "okc") },
    h("h2", {}, T("Sensori verso Home Assistant", "Sensors to Home Assistant")),
    h("div", { class: "table-wrap" }, h("table", {}, h("tbody", {},
      facts.map(([k, v]) => h("tr", {}, h("th", {}, k), h("td", {}, v)))))));
}

function renderHistory() {
  if (!state.scans.length) {
    return [haCard(), h("div", { class: "card empty" }, T("Nessuna scansione eseguita.", "No scan has run."))];
  }
  const heads = [T("Data", "Date"), T("Durata", "Duration"), T("Dispositivi", "Devices"),
    T("Critici/alti", "Critical/high"), T("Medi", "Medium"), T("Bassi/info", "Low/info")];
  return [haCard(), h("div", { class: "card table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, heads.map((t) => h("th", {}, t)))),
    h("tbody", {}, [...state.scans].reverse().map((s) => h("tr", {},
      h("td", {}, fmt(s.ts)), h("td", {}, s.duration + " s"), h("td", {}, s.devices),
      h("td", {}, s.counts.critical + s.counts.high), h("td", {}, s.counts.medium),
      h("td", {}, s.counts.low + s.counts.info))))))];
}

// ---------------------------------------------------------------- ciclo principale

const VIEWS = { findings: renderFindings, incidents: renderIncidents, devices: renderDevices,
  router: renderRouter, history: renderHistory };

function render() {
  if (!state) return;
  renderSummary();
  $("view").replaceChildren(...VIEWS[tab]());
}

async function refresh(force) {
  try {
    const next = await api("api/state");
    const json = JSON.stringify(next);
    const active = document.activeElement;
    const typing = active && active.matches("input[type=text], select");
    if (!force && (json === lastJson || typing || $("confirm").open)) return;
    if (next.lang !== LANG || !state) {
      LANG = next.lang === "it" ? "it" : "en";
      applyStaticTexts();
    }
    state = next;
    lastJson = json;
    render();
  } catch (err) {
    banner(T("Impossibile leggere lo stato: ", "Cannot read the status: ") + err.message, "error");
  }
}

document.querySelectorAll(".tabs button").forEach((btn) => btn.addEventListener("click", () => {
  tab = btn.dataset.tab;
  document.querySelectorAll(".tabs button").forEach((b) => b.setAttribute("aria-selected", String(b === btn)));
  render();
}));
$("scan").addEventListener("click", () => act("api/scan", {}));

refresh(true);
setInterval(refresh, 4000);
