"use strict";

// Tutto il testo passa da textContent: nomi host e banner arrivano da dispositivi non fidati.
function setAttrs(el, attrs) {
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === false || v == null) continue;
    if (k === "class") el.setAttribute("class", v);
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "checked" || k === "disabled" || k === "open" || k === "hidden") el[k] = !!v;
    else el.setAttribute(k, v);
  }
}
function append(el, children) {
  for (const c of children.flat(Infinity)) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}
function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  setAttrs(el, attrs);
  return append(el, children);
}
function s(tag, attrs, ...children) {
  const el = document.createElementNS("http://www.w3.org/2000/svg", tag);
  setAttrs(el, attrs);
  return append(el, children);
}

// Lingua dell'interfaccia: la decide il backend (opzione dell'add-on o lingua di Home Assistant).
let LANG = "en";
const T = (it, en) => (LANG === "it" ? it : en);
const N = (n, itOne, itMany, enOne, enMany) => `${n} ${n === 1 ? T(itOne, enOne) : T(itMany, enMany)}`;
const sevLabel = (v) => ({
  critical: T("Critico", "Critical"), high: T("Alto", "High"), medium: T("Medio", "Medium"),
  low: T("Basso", "Low"), info: "Info",
}[v] || v);
const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const $ = (id) => document.getElementById(id);
const fmt = (ts) => ts
  ? new Date(ts * 1000).toLocaleString(LANG === "it" ? "it-IT" : undefined, { dateStyle: "short", timeStyle: "short" })
  : "-";

// ---------------------------------------------------------------- icone

const ICONS = {
  router: "M4 14h16v5H4z M8 14V8 M16 14V8 M7.500 16.500h.01 M11 16.500h.01",
  computer: "M3 5h18v11H3z M8 20h8 M12 16v4",
  telefono: "M8 3h8v18H8z M11 18h2",
  tv: "M3 7h18v11H3z M8 21h8 M9 3l3 4 3-4",
  audio: "M7 3h10v18H7z M9 15a3 3 0 1 0 6 0 3 3 0 1 0-6 0 M12 7h.01",
  stampante: "M7 8V3h10v5 M5 8h14v8H5z M7 14h10v6H7z",
  telecamera: "M3 8h12v8H3z M15 11l6-3v8l-6-3",
  nas: "M4 4h16v6H4z M4 14h16v6H4z M7 7h.01 M7 17h.01",
  iot: "M9 18h6 M10 21h4 M12 3a6 6 0 0 0-4 10.500V15h8v-1.500A6 6 0 0 0 12 3z",
  hub: "M3 11l9-7 9 7 M5 10v10h14V10 M10 20v-6h4v6",
  console: "M6 8h12a4 4 0 0 1 4 4v2a3 3 0 0 1-5.500 1.500L15 14H9l-1.500 1.500A3 3 0 0 1 2 14v-2a4 4 0 0 1 4-4z M7 10.500v3 M5.500 12h3 M16.500 12h.01",
  server: "M4 3h16v5H4z M4 10h16v5H4z M4 17h16v4H4z M7 5.500h.01 M7 12.500h.01",
  sconosciuto: "M3 12a9 9 0 1 0 18 0 9 9 0 1 0-18 0 M9.500 9.500a2.500 2.500 0 1 1 3.500 2.300c-.7.4-1 .9-1 1.700 M12 17h.01",
  alert: "M12 4 2.500 20h19z M12 10v4.500 M12 17.500h.01",
  note: "M3 12a9 9 0 1 0 18 0 9 9 0 1 0-18 0 M12 11v5 M12 8h.01",
  check: "M5 12.500l4.500 4.500L19 7.500",
  eye: "M2 12s3.600-6.500 10-6.500S22 12 22 12s-3.600 6.500-10 6.500S2 12 2 12z M9.500 12a2.500 2.500 0 1 0 5 0 2.500 2.500 0 1 0-5 0",
  list: "M9 6h11 M9 12h11 M9 18h11 M4.500 6h.01 M4.500 12h.01 M4.500 18h.01",
  chevron: "M9 6l6 6-6 6",
  lan: "M12 3v6 M5 15v-3h14v3 M12 9v3 M3 15h4v5H3z M10 15h4v5h-4z M17 15h4v5h-4z M10 3h4v0",
  zigbee: "M5 6h14L5 18h14",
  zwave: "M2.500 12c2.300-5 4.700-5 7 0s4.700 5 7 0c1.200-2.500 2.300-3.700 5-3.700",
  matter: "M12 4.500 4.500 18h15z M12 4.500v6.500 M4.500 18l7.500-7 7.500 7",
  bluetooth: "M7 7.500l10 9-5 4.500V3l5 4.500-10 9",
  mqtt: "M5 19h.01 M5 13a6 6 0 0 1 6 6 M5 7a12 12 0 0 1 12 12 M5 3.500a15.500 15.500 0 0 1 15.500 15.500",
  battery: "M3 8h15v8H3z M21 11v2 M6 11v2",
  access: "M6 11h12v9H6z M8.500 11V8a3.500 3.500 0 0 1 7 0v3 M12 14.500v2",
  open: "M14 4h6v6 M20 4l-9 9 M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5",
};
function icon(name) {
  return s("svg", { viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", "stroke-width": "1.8",
    "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true" },
    s("path", { d: ICONS[name] || ICONS.sconosciuto }));
}
const chevron = () => h("span", { class: "chev" }, icon("chevron"));

// ---------------------------------------------------------------- stato e azioni

let state = null;
let lastJson = "";
let tab = "findings";
let showClosed = false;
let devQuery = "";
let devType = "";
let devFilter = "all";
let section = "lan";
let smartFilter = "all";
const openRows = new Set();

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

function toast(text, kind) {
  if (!text) return;
  const el = h("div", { class: "toast " + (kind || "") }, h("span", {}, text),
    h("button", { "aria-label": T("Chiudi", "Close"), onclick: () => el.remove() }, "×"));
  $("toasts").append(el);
  setTimeout(() => el.remove(), kind === "error" ? 9000 : 4500);
}

async function act(path, body, okText) {
  try {
    const res = await api(path, body);
    toast(res.message || okText);
  } catch (err) {
    toast(err.message, "error");
  }
  await refresh(true);
}

function confirmDialog(title, text, yes) {
  return new Promise((resolve) => {
    const dlg = $("confirm");
    $("confirm-title").textContent = title;
    $("confirm-text").textContent = text;
    $("confirm-yes").textContent = yes || T("Conferma", "Confirm");
    $("confirm-no").textContent = T("Annulla", "Cancel");
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
const openFindings = (key) => state.findings.filter((f) => f.device_key === key && f.status === "open");
// Ogni rete è una sezione: problemi e incidenti senza rete appartengono alla rete locale.
const netOf = (x) => x.network || "lan";
const secFindings = () => state.findings.filter((f) => netOf(f) === section);
const secIncidents = () => state.incidents.filter((i) => netOf(i) === section);
const networks = () => (state.smarthome ? state.smarthome.networks : []);
// Gli accessi a Home Assistant sono una sezione come le reti: i "dispositivi" sono gli indirizzi di provenienza.
function accessNet() {
  const a = state.access;
  return a ? { key: "access", label: T("Accessi", "Access"), access: a, devices: a.sources, summary: { total: a.sources.length } } : null;
}
const currentNet = () => (section === "access" ? accessNet() : networks().find((n) => n.key === section));
const smartFindings = (id) => state.findings.filter((f) => f.status === "open" && f.ha_device && f.ha_device.id === id);
function worst(findings) {
  return findings.reduce((best, f) => (best === null || SEV_RANK[f.severity] < SEV_RANK[best] ? f.severity : best), null);
}

const factList = (facts) => h("dl", { class: "facts" }, facts.map(([k, v]) => [h("dt", {}, k), h("dd", {}, v)]));

// Riga espandibile che ricorda se era aperta tra un aggiornamento e l'altro.
function row(id, cls, summary, body) {
  const el = h("details", { class: "row " + (cls || ""), open: openRows.has(id), "data-id": id },
    h("summary", {}, summary, chevron()), h("div", { class: "body" }, body));
  el.addEventListener("toggle", () => (el.open ? openRows.add(id) : openRows.delete(id)));
  return el;
}

function go(name, rowId) {
  tab = name;
  if (rowId) openRows.add(rowId);
  render();
  const target = rowId && document.querySelector(`[data-id="${CSS.escape(rowId)}"]`);
  (target || document.querySelector(".tabs")).scrollIntoView({ behavior: "smooth", block: target ? "center" : "start" });
}

// ---------------------------------------------------------------- radar

function hash(text) {
  let x = 2166136261;
  for (let i = 0; i < text.length; i++) x = Math.imul(x ^ text.charCodeAt(i), 16777619);
  return x >>> 0;
}

function radar(nodes, center, label, emptyText) {
  const svg = s("svg", { viewBox: "0 0 400 400", class: "radar" + (state.status.running ? " scanning" : ""), role: "img",
    "aria-label": label },
    s("defs", {}, s("radialGradient", { id: "radar-bg" },
      s("stop", { offset: "0", "stop-color": "#1b3260" }), s("stop", { offset: "1", "stop-color": "#0a1428" }))),
    s("circle", { class: "disc", cx: 200, cy: 200, r: 199 }),
    [62, 122, 186].map((r) => s("circle", { class: "ring", cx: 200, cy: 200, r })),
    s("line", { class: "axis", x1: 200, y1: 14, x2: 200, y2: 386 }),
    s("line", { class: "axis", x1: 14, y1: 200, x2: 386, y2: 200 }),
    s("g", { class: "sweep" },
      s("path", { d: "M200 200 L200 14 A186 186 0 0 1 342.500 80.400 Z", fill: "rgba(62,214,160,.16)" }),
      s("line", { x1: 200, y1: 200, x2: 342.5, y2: 80.4, stroke: "rgba(62,214,160,.9)", "stroke-width": 2 })));
  if (!nodes.length && !center) {
    svg.append(s("text", { class: "empty", x: 200, y: 206 }, emptyText));
    return svg;
  }
  if (center) {
    svg.append(s("rect", { class: "home", x: 189, y: 189, width: 22, height: 22, rx: 6, onclick: center.run },
      s("title", {}, center.title)));
  }
  for (const n of nodes) {
    // Vicino al centro ciò che è a posto, sul perimetro ciò che chiede attenzione.
    const [lo, hi] = n.inner ? [44, 112] : [134, 178];
    const angle = (hash(n.key) % 3600) / 10 * Math.PI / 180;
    const dist = lo + (hash(n.key + "r") % 1000) / 1000 * (hi - lo);
    const cx = 200 + dist * Math.cos(angle), cy = 200 + dist * Math.sin(angle);
    if (n.pulse) svg.append(s("circle", { class: "pulse", cx, cy, r: 7 }));
    svg.append(s("circle", { class: "blip " + n.cls, cx, cy, r: n.cls === "bad" ? 8 : 6.5, onclick: n.run },
      s("title", {}, n.title)));
  }
  return svg;
}

function lanRadar() {
  const online = state.devices.filter((d) => d.online);
  const gateway = online.find((d) => d.is_gateway);
  const nodes = online.filter((d) => !d.is_gateway).map((d) => {
    const sev = worst(openFindings(d.key));
    return { key: d.key, title: `${deviceLabel(d)} - ${d.ip}`, inner: d.trusted, pulse: d.needs_review,
      cls: sev === "critical" || sev === "high" ? "bad" : sev === "medium" ? "warn" : d.trusted ? "ok" : "new",
      run: () => focusDevice(d.key) };
  });
  return radar(nodes, gateway ? { title: `${deviceLabel(gateway)} - ${gateway.ip}`, run: () => focusDevice(gateway.key) } : null,
    T(`Radar della rete: ${online.length} dispositivi accesi`, `Network radar: ${online.length} devices online`),
    T("Nessun dispositivo ancora", "No devices yet"));
}

function netRadar(net) {
  if (net.access) {
    const sources = net.devices.map((x) => ({ key: x.ip, inner: !x.external, cls: x.banned || x.count >= 5 ? "bad" : "warn",
      title: `${x.ip} - ${N(x.count, "tentativo", "tentativi", "attempt", "attempts")}`, run: () => go("devices", "a:" + x.ip) }));
    return radar(sources, { title: "Home Assistant", run: () => go("devices") },
      T(`Accessi: ${sources.length} indirizzi con tentativi falliti`, `Access: ${sources.length} addresses with failed attempts`), "");
  }
  const nodes = net.devices.map((d) => {
    const bad = d.offline || d.silent, warn = d.battery_low || d.weak;
    return { key: d.id, title: d.name, inner: !bad && !warn, cls: bad ? "bad" : warn ? "warn" : "ok",
      run: () => focusSmart(d.id) };
  });
  return radar(nodes, net.devices.length ? { title: "Home Assistant", run: () => go("devices") } : null,
    T(`Rete ${net.label}: ${net.devices.length} dispositivi`, `${net.label} network: ${net.devices.length} devices`),
    T("Nessun dispositivo", "No devices"));
}

// ---------------------------------------------------------------- hero

function verdict() {
  const net = currentNet();
  const open = secFindings().filter((f) => f.status === "open");
  const grave = open.filter((f) => SEV_RANK[f.severity] <= 1).length;
  const medium = open.filter((f) => f.severity === "medium").length;
  const pending = secIncidents().filter((i) => !i.acknowledged).length;
  if (state.status.running) {
    return { title: (state.status.phase || T("Scansione in corso", "Scan in progress")) + "...",
      sub: T("Sto controllando la rete: i risultati compaiono qui appena pronti.",
        "Checking the network: results will appear here as soon as they are ready.") };
  }
  if (section === "lan" && !state.scans.length) {
    return { title: T("Pronta a controllare la tua rete", "Ready to check your network"),
      sub: T("La prima scansione elenca i dispositivi collegati e cerca i servizi a rischio. Richiede un paio di minuti.",
        "The first scan lists the connected devices and looks for risky services. It takes a couple of minutes.") };
  }
  if (net && net.access && !net.access.read_at) {
    return { title: T("Non ho ancora letto il log di Home Assistant", "The Home Assistant log has not been read yet"),
      sub: net.access.error || T("Il primo controllo parte con la prossima scansione.", "The first check runs with the next scan.") };
  }
  if (net && net.access && !net.devices.length && !open.length && !pending) {
    return { title: T("Nessun tentativo di accesso sospetto", "No suspicious login attempts"),
      sub: T("Nelle ultime 24 ore Home Assistant non ha registrato richieste con credenziali non valide.",
        "In the last 24 hours Home Assistant recorded no requests with invalid credentials.") };
  }
  if (net && !net.access && !net.devices.length) {
    return { title: T(`Nessun dispositivo ${net.label} trovato`, `No ${net.label} devices found`),
      sub: state.smarthome.read_at
        ? T(`Leggo i dispositivi da Home Assistant: appena un'integrazione ${net.label} ne aggiunge uno, compare qui.`,
          `Devices are read from Home Assistant: as soon as a ${net.label} integration adds one, it shows up here.`)
        : T("Il registro di Home Assistant non è ancora stato letto: avvia una scansione.",
          "The Home Assistant registry has not been read yet: start a scan.") };
  }
  const parts = [];
  if (grave) parts.push(N(grave, "problema grave", "problemi gravi", "serious finding", "serious findings"));
  if (pending) parts.push(N(pending, "incidente da verificare", "incidenti da verificare", "incident to review", "incidents to review"));
  if (medium) parts.push(N(medium, "problema medio", "problemi medi", "medium finding", "medium findings"));
  const low = open.length - grave - medium;
  if (net && low) parts.push(N(low, "avviso minore", "avvisi minori", "minor notice", "minor notices"));
  const name = !net ? T("La rete", "Your network")
    : net.access ? T("L'accesso a Home Assistant", "Access to Home Assistant")
      : T(`La rete ${net.label}`, `Your ${net.label} network`);
  const title = grave || pending ? T(`${name} richiede attenzione`, `${name} needs attention`)
    : medium ? T("Qualche punto da sistemare", "A few things to tidy up")
      : T(`${name} è in ordine`, `${name} looks good`);
  return { title, sub: parts.length ? parts.join(", ") + "."
    : T("Nessun problema aperto e nessun incidente da verificare.", "No open findings and no incidents to review.") };
}

function todoItems() {
  if (state.status.running || (section === "lan" && !state.scans.length)) return [];
  const items = [];
  const pending = secIncidents().filter((i) => !i.acknowledged);
  if (pending.length) {
    items.push({ sev: pending[0].severity, icon: "eye", title: pending[0].title,
      sub: pending.length === 1 ? T("Incidente da verificare", "Incident to review")
        : pending.length === 2 ? T("e un altro incidente da verificare", "and one more incident to review")
          : T(`e altri ${pending.length - 1} incidenti da verificare`, `and ${pending.length - 1} more incidents to review`),
      run: () => go("incidents") });
  }
  const limit = section === "lan" ? 2 : 3;
  for (const f of secFindings().filter((x) => x.status === "open" && SEV_RANK[x.severity] <= limit)) {
    if (items.length >= 3) break;
    const dev = state.devices.find((d) => d.key === f.device_key);
    items.push({ sev: f.severity, icon: f.id.startsWith("sh:battery") ? "battery" : "alert", title: f.title,
      sub: f.ha_device ? f.ha_device.name : dev ? deviceLabel(dev) : "Router", run: () => go("findings", "f:" + f.id) });
  }
  if (section !== "lan") return items;
  const unknown = state.devices.filter((d) => d.online && !d.trusted).length;
  if (unknown && items.length < 3) {
    items.push({ sev: "info", icon: "list",
      title: N(unknown, "dispositivo da classificare", "dispositivi da classificare", "device to classify", "devices to classify"),
      sub: T("Dai un nome a quelli che riconosci e segnali come fidati", "Name the ones you recognise and mark them as trusted"),
      run: () => { devFilter = "new"; devQuery = ""; devType = ""; go("devices"); } });
  }
  const done = state.checklist.filter((i) => i.done).length;
  if (done < state.checklist.length && items.length < 3) {
    items.push({ sev: "info", icon: "check",
      title: T(`Verifiche manuali sul router: ${done} di ${state.checklist.length}`, `Manual router checks: ${done} of ${state.checklist.length}`),
      sub: T("Impostazioni che solo tu puoi controllare dal pannello del router", "Settings only you can check from the router's panel"),
      run: () => go("router") });
  }
  return items;
}

function heroStats() {
  const net = currentNet();
  if (net && net.access) {
    const a = net.access;
    if (!a.read_at) return null;
    return h("div", { class: "stats" },
      h("span", {}, h("b", {}, a.attempts_24h), " ", T("tentativi falliti in 24 ore", "failed attempts in 24 hours")),
      h("span", {}, h("b", {}, a.external_24h), " ", T("da Internet", "from the Internet")),
      h("span", {}, h("b", {}, a.banned.length), " ", T("indirizzi bloccati", "banned addresses")),
      h("span", {}, T("Ultimo controllo ", "Last check "), h("b", {}, fmt(a.read_at))));
  }
  if (net) {
    const sum = net.summary;
    if (!sum.total) return null;
    return h("div", { class: "stats" },
      h("span", {}, h("b", {}, sum.total), " ", T("dispositivi", "devices")),
      h("span", {}, h("b", {}, sum.unreachable + sum.silent), " ", T("non comunicano", "not communicating")),
      sum.battery_powered ? h("span", {}, h("b", {}, `${sum.low_battery}/${sum.battery_powered}`), " ", T("batterie scariche", "low batteries")) : null,
      h("span", {}, T("Ultimo controllo ", "Last check "), h("b", {}, fmt(state.smarthome.read_at))));
  }
  const last = state.scans[state.scans.length - 1];
  if (!last) return null;
  return h("div", { class: "stats" },
    h("span", {}, T("Punteggio ", "Score "), h("b", {}, state.score), "/100"),
    h("span", {}, h("b", {}, state.devices.filter((d) => d.online).length), " ", T("dispositivi in rete", "devices online")),
    h("span", {}, T("Ultima scansione ", "Last scan "), h("b", {}, fmt(last.ts))),
    state.status.next_scan ? h("span", {}, T("Prossima ", "Next "), h("b", {}, fmt(state.status.next_scan))) : null);
}

function renderHero() {
  const v = verdict();
  const net = currentNet();
  const todo = todoItems();
  const legend = net && net.access
    ? [["warn", T("pochi tentativi", "a few attempts")], ["bad", T("molti tentativi o bloccato", "many attempts or banned")]]
    : net
    ? [["ok", T("funziona", "working")], ["warn", T("batteria o segnale", "battery or signal")],
      ["bad", T("non comunica", "not communicating")]]
    : [["ok", T("fidato, nessun problema", "trusted, no findings")], ["warn", T("da sistemare", "needs fixing")],
      ["bad", T("grave", "serious")], ["new", T("da classificare (anello esterno)", "to classify (outer ring)")]];
  const hasNodes = net ? net.devices.length : state.devices.some((d) => d.online);
  $("hero").replaceChildren(
    h("div", { class: "radar-wrap" }, net ? netRadar(net) : lanRadar(),
      hasNodes ? h("div", { class: "legend" }, legend.map(([cls, text]) => h("span", {}, h("i", { class: "dot " + cls }), text)),
        net ? h("span", {}, net.access ? T("anello esterno: da Internet", "outer ring: from the Internet")
          : T("anello esterno: richiede attenzione", "outer ring: needs attention")) : null) : null),
    h("div", {},
      h("h2", { class: "verdict" }, v.title),
      h("p", { class: "verdict-sub" }, v.sub),
      state.status.error ? h("p", { class: "verdict-sub critical" },
        h("span", { class: "pill" }, T("Ultima scansione non riuscita", "Last scan failed")), " ", state.status.error) : null,
      todo.length ? h("ul", { class: "todo" }, todo.map((item) => h("li", {},
        h("button", { onclick: item.run },
          h("span", { class: "sev-mark " + item.sev }, icon(item.icon)),
          h("span", { class: "what" }, h("b", {}, item.title), h("span", { class: "small muted" }, item.sub)),
          chevron())))) : null,
      heroStats(),
      section === "lan" && !state.scans.length && !state.status.running ? h("div", { class: "hero-actions" },
        h("button", { class: "btn primary", onclick: startScan }, T("Avvia la prima scansione", "Start the first scan"))) : null));

  const btn = $("scan");
  btn.disabled = state.status.running;
  btn.replaceChildren(...(state.status.running
    ? [h("span", { class: "spinner" }), T("Scansione in corso", "Scan in progress")]
    : [T("Avvia scansione", "Start scan")]));
}

const startScan = () => act("api/scan", {});

// ---------------------------------------------------------------- problemi

function findingRow(f) {
  const dev = state.devices.find((d) => d.key === f.device_key);
  const portText = f.port && f.category !== "router" ? T(", porta ", ", port ") + f.port : "";
  const where = f.ha_device ? f.ha_device.name
    : dev ? `${deviceLabel(dev)} (${dev.ip})${portText}` : (f.category === "router" ? "Router" : f.ip || "");
  const closed = f.status !== "open";
  const buttons = [];
  if (f.status === "open") {
    if (f.action) {
      buttons.push(h("button", { class: "btn danger small", onclick: async () => {
        const port = `${f.action.external_port}/${f.action.protocol}`;
        const ok = await confirmDialog(f.action.label + "?", T(
          `Verrà chiesto al router di chiudere la porta ${port}. Il servizio che la usa non sarà più raggiungibile da Internet.`,
          `The router will be asked to close port ${port}. The service using it will no longer be reachable from the Internet.`),
          f.action.label);
        if (ok) act("api/action", { id: f.id, confirm: true });
      } }, f.action.label));
    }
    if (f.id.startsWith("new-device:")) {
      buttons.push(h("button", { class: "btn small", onclick: () => act("api/device", { key: f.device_key, trusted: true },
        T("Segnato come fidato", "Marked as trusted")) }, T("Lo riconosco, è fidato", "I recognise it, it's trusted")));
    }
    if (dev) buttons.push(h("button", { class: "btn small", onclick: () => focusDevice(dev.key) }, T("Vedi il dispositivo", "View the device")));
    if (f.ha_device && f.ha_device.id) buttons.push(h("button", { class: "btn small", onclick: () => focusSmart(f.ha_device.id) }, T("Vedi il dispositivo", "View the device")));
    buttons.push(h("button", { class: "btn small", onclick: () => act("api/finding", { id: f.id, status: "ignored" },
      T("Problema ignorato", "Finding ignored")) }, T("Ignora", "Ignore")));
  } else if (f.status === "ignored") {
    buttons.push(h("button", { class: "btn small", onclick: () => act("api/finding", { id: f.id, status: "open" },
      T("Problema riaperto", "Finding reopened")) }, T("Riapri", "Reopen")));
  }
  return row("f:" + f.id, closed ? "dim" : "", [
    h("span", { class: "sev-mark " + f.severity }, icon(f.id.startsWith("sh:battery") ? "battery" : SEV_RANK[f.severity] <= 1 ? "alert" : "note")),
    h("span", { class: "main" }, h("div", { class: "title" }, f.title), h("div", { class: "sub" }, where)),
    h("span", { class: "tags" },
      closed ? h("span", { class: "pill plain" }, f.status === "ignored" ? T("Ignorato", "Ignored") : T("Risolto", "Resolved"))
        : h("span", { class: "pill " + f.severity }, sevLabel(f.severity))),
  ], [
    h("p", {}, f.detail),
    h("div", { class: "fix" }, h("h3", {}, T("Come rimediare", "How to fix")),
      h("ol", { class: "steps" }, f.remediation.map((step) => h("li", {}, step)))),
    h("div", { class: "actions" }, buttons, h("span", { class: "small muted" }, T("Rilevato il ", "Detected on ") + fmt(f.first_seen))),
  ]);
}

function renderFindings() {
  const open = secFindings().filter((f) => f.status === "open");
  const closed = secFindings().filter((f) => f.status !== "open");
  const out = [h("div", { class: "toolbar" }, h("div", { class: "chips" },
    h("button", { class: "chip", "aria-pressed": String(!showClosed), onclick: () => { showClosed = false; render(); } },
      T(`Aperti (${open.length})`, `Open (${open.length})`)),
    h("button", { class: "chip", "aria-pressed": String(showClosed), onclick: () => { showClosed = true; render(); } },
      T(`Ignorati e risolti (${closed.length})`, `Ignored and resolved (${closed.length})`))))];
  const list = showClosed ? closed : open;
  if (!list.length) {
    out.push(h("div", { class: "panel empty" }, showClosed
      ? [h("b", {}, T("Niente in archivio", "Nothing archived")), T("Qui finiscono i problemi che ignori o che la scansione non trova più.",
        "Findings you ignore, or that the scan no longer detects, end up here.")]
      : section !== "lan" ? [h("b", {}, T("Nessun problema aperto", "No open findings")),
        T("Qui compaiono dispositivi che non comunicano, batterie in esaurimento, segnale debole e aggiornamenti.",
          "Devices not communicating, low batteries, weak signal and updates appear here.")]
      : state.scans.length
        ? [h("b", {}, T("Nessun problema aperto", "No open findings")), T("Controlla anche le verifiche manuali nella scheda Router.",
          "Also go through the manual checks in the Router tab.")]
        : [h("b", {}, T("Ancora nessuna scansione", "No scan yet")), T("Avvia una scansione per controllare la rete.", "Start a scan to check the network.")]));
  } else {
    out.push(h("div", { class: "panel" }, list.map(findingRow)));
  }
  return out;
}

// ---------------------------------------------------------------- incidenti

function renderIncidents() {
  const all = secIncidents();
  if (!all.length) {
    return [h("div", { class: "panel empty" }, h("b", {}, T("Nessun incidente", "No incidents")), section === "lan" ? T(
      "Qui compaiono i cambiamenti sospetti tra una scansione e l'altra: nuovi dispositivi, nuove porte, nuove aperture verso Internet.",
      "Suspicious changes between one scan and the next appear here: new devices, new ports, new forwards to the Internet.")
      : T("Qui compaiono i cambiamenti tra un controllo e l'altro: nuovi dispositivi, dispositivi che smettono di rispondere, cali di batteria.",
        "Changes between one check and the next appear here: new devices, devices that stop responding, battery drops."))];
  }
  const pending = all.filter((i) => !i.acknowledged);
  const out = [];
  if (pending.length > 1) {
    out.push(h("div", { class: "toolbar" }, h("button", { class: "btn small",
      onclick: async () => { for (const i of pending) await api("api/incident", { id: i.id }).catch(() => {});
        toast(T("Incidenti segnati come verificati", "Incidents marked as reviewed")); refresh(true); } },
      T(`Segna tutti come verificati (${pending.length})`, `Mark all as reviewed (${pending.length})`))));
  }
  out.push(h("div", { class: "panel" }, all.map((i) => {
    if (!i.acknowledged && !openRows.has("i-seen:" + i.id)) { openRows.add("i:" + i.id); openRows.add("i-seen:" + i.id); }
    return row("i:" + i.id, i.acknowledged ? "dim" : "", [
      h("span", { class: "sev-mark " + (i.acknowledged ? "info" : i.severity) }, icon("eye")),
      h("span", { class: "main" }, h("div", { class: "title" }, i.title),
        h("div", { class: "sub" }, fmt(i.ts) + (i.device ? `, ${i.device}${i.ip ? " (" + i.ip + ")" : ""}` : ""))),
      h("span", { class: "tags" }, i.acknowledged ? h("span", { class: "pill plain" }, T("Verificato", "Reviewed"))
        : h("span", { class: "pill " + i.severity }, sevLabel(i.severity))),
    ], [
      h("p", {}, i.detail),
      h("div", { class: "actions" },
        i.acknowledged ? null : h("button", { class: "btn primary small",
          onclick: () => act("api/incident", { id: i.id }, T("Incidente segnato come verificato", "Incident marked as reviewed")) },
          T("Ho verificato", "I have reviewed it")),
        i.device_key && state.devices.some((d) => d.key === i.device_key)
          ? h("button", { class: "btn small", onclick: () => focusDevice(i.device_key) }, T("Vedi il dispositivo", "View the device")) : null,
        i.ha_device && (currentNet() || { devices: [] }).devices.some((d) => d.id === i.ha_device)
          ? h("button", { class: "btn small", onclick: () => focusSmart(i.ha_device) }, T("Vedi il dispositivo", "View the device")) : null),
    ]);
  })));
  return out;
}

// ---------------------------------------------------------------- dispositivi

function focusDevice(key) {
  section = "lan";
  devQuery = ""; devType = ""; devFilter = "all";
  go("devices", "d:" + key);
}

function haLinks(d) {
  const link = d.ha;
  if (!link) return null;
  if (!link.linked) {
    return h("div", { class: "halink muted" }, T(
      "Non è collegato a nessuna integrazione di Home Assistant.", "Not linked to any Home Assistant integration."));
  }
  const rows = link.devices.map((x) => h("div", {},
    h("b", {}, T("In Home Assistant: ", "In Home Assistant: ")),
    // Il pannello è in un iframe: il collegamento apre la pagina del dispositivo nella finestra principale.
    h("a", { href: "/config/devices/device/" + encodeURIComponent(x.id), target: "_top" }, x.name || x.id),
    [x.manufacturer, x.model].filter(Boolean).length ? ` (${[x.manufacturer, x.model].filter(Boolean).join(" ")})` : "",
    x.integrations.length ? T(", integrazioni: ", ", integrations: ") + x.integrations.join(", ") : "",
    x.area ? T(", area: ", ", area: ") + x.area : "",
    h("span", { class: "muted" }, T(", riconosciuto per ", ", matched by ") + x.match.join(", ")),
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

function deviceRow(d) {
  const info = d.info || {};
  const type = d.is_gateway ? "router" : (info.type || "sconosciuto");
  const findings = openFindings(d.key);
  const sev = worst(findings);
  const nameInput = h("input", { type: "text", value: d.name || "",
    placeholder: T("Dai un nome (es. TV salotto)", "Give it a name (e.g. Living room TV)"),
    "aria-label": T("Nome del dispositivo", "Device name") });
  nameInput.addEventListener("change", () => act("api/device", { key: d.key, name: nameInput.value }, T("Nome salvato", "Name saved")));
  const facts = [
    [T("Indirizzo", "Address"), [d.ip, d.mac].filter(Boolean).join(", ")],
    [T("Produttore", "Vendor"), info.manufacturer || d.vendor],
    [T("Modello", "Model"), info.model],
    [T("Nome annunciato", "Announced name"), info.friendly_name],
    [T("Nome in rete", "Network name"), d.hostname],
    [T("Sistema operativo", "Operating system"), info.os ? `${info.os} (${T("stima", "estimate")} ${info.os_accuracy || "?"}%)` : ""],
    ["Firmware", info.firmware],
    [T("Nome Windows", "Windows name"), [info.netbios, info.workgroup].filter(Boolean).join(T(", gruppo ", ", workgroup "))],
    [T("Servizi annunciati", "Announced services"), (info.services || []).join(", ")],
    [T("MAC casuale", "Random MAC"), info.private_mac ? T(
      "sì: può cambiare e far ricomparire il dispositivo come nuovo", "yes: it can change and make the device show up as new again") : ""],
    [T("Visto la prima volta", "First seen"), fmt(d.first_seen)],
    d.online ? null : [T("Visto l'ultima volta", "Last seen"), fmt(d.last_seen)],
  ].filter((x) => x && x[1]);
  const sub = [d.ip, d.is_gateway ? null : info.type_label, info.model || d.vendor].filter(Boolean).join(", ");
  return row("d:" + d.key, d.online ? "" : "dim", [
    h("span", { class: "type-icon" + (d.online ? "" : " off"), title: info.type_label || "" }, icon(type)),
    h("span", { class: "main" }, h("div", { class: "title" }, deviceLabel(d)), h("div", { class: "sub" }, sub)),
    h("span", { class: "tags" },
      findings.length ? h("span", { class: "pill " + sev },
        N(findings.length, "problema", "problemi", "finding", "findings")) : null,
      d.trusted ? null : h("span", { class: "pill medium" }, T("Da classificare", "To classify")),
      d.ha && d.ha.linked ? h("span", { class: "pill okc optional" }, T("In domotica", "Smart home")) : null,
      d.is_self ? h("span", { class: "pill plain optional" }, "Home Assistant") : null,
      h("i", { class: "status-dot" + (d.online ? " on" : ""), title: d.online ? T("Acceso", "Online") : T("Spento", "Offline") })),
  ], [
    h("div", { class: "actions" },
      nameInput,
      h("button", { class: "btn small" + (d.trusted ? "" : " primary"),
        onclick: () => act("api/device", { key: d.key, trusted: !d.trusted },
          d.trusted ? T("Tolto dai fidati", "Removed from trusted") : T("Segnato come fidato", "Marked as trusted")) },
        d.trusted ? T("Togli da fidati", "Remove from trusted") : T("Segna come fidato", "Mark as trusted")),
      d.online ? null : h("button", { class: "btn small", onclick: async () => {
        if (await confirmDialog(T("Dimenticare il dispositivo?", "Forget this device?"), T(
          "Verrà rimosso dall'elenco insieme ai suoi problemi. Se si ricollega, sarà segnalato come nuovo.",
          "It will be removed from the list together with its findings. If it reconnects, it will be reported as new."),
          T("Dimentica", "Forget")))
          act("api/device/forget", { key: d.key }, T("Dispositivo dimenticato", "Device forgotten"));
      } }, T("Dimentica", "Forget"))),
    findings.length ? h("div", { class: "actions" }, findings.map((f) =>
      h("button", { class: "btn small", onclick: () => go("findings", "f:" + f.id) },
        h("span", { class: "pill " + f.severity }, sevLabel(f.severity)), f.title))) : null,
    h("dl", { class: "facts" }, facts.map(([k, v]) => [h("dt", {}, k), h("dd", {}, v)])),
    haLinks(d),
    d.ports && d.ports.length ? h("div", {},
      h("div", { class: "small muted" }, T("Porte aperte", "Open ports")),
      h("div", { class: "ports" }, d.ports.map((p) => {
        const cert = p.info.cert_subject
          ? ` | ${T("certificato", "certificate")}: ${p.info.cert_subject}${p.info.cert_self_signed ? T(" (autofirmato)", " (self-signed)") : ""}` +
            (p.info.cert_expires ? T(", scade il ", ", expires on ") + fmt(p.info.cert_expires) : "") : "";
        const extra = [p.info.product, p.info.title || p.info.server || p.info.banner].filter(Boolean).join(" | ") + cert;
        return h("span", { class: "port" + (p.info.cert_expired ? " expired" : ""), title: extra },
          `${p.port} ${p.service}${p.info.product ? ", " + p.info.product : ""}`);
      }))) : h("div", { class: "small muted" }, T("Nessuna porta aperta tra quelle controllate.", "No open port among those checked.")),
  ]);
}

function deviceList() {
  const q = devQuery.trim().toLowerCase();
  const typeOf = (d) => (d.is_gateway ? "router" : (d.info && d.info.type) || "sconosciuto");
  const shown = state.devices.filter((d) => {
    if (devType && typeOf(d) !== devType) return false;
    if (devFilter === "new" && d.trusted) return false;
    if (devFilter === "issues" && !openFindings(d.key).length) return false;
    if (devFilter === "linked" && !(d.ha && d.ha.linked)) return false;
    if (devFilter === "unlinked" && (d.ha && d.ha.linked)) return false;
    if (!q) return true;
    const info = d.info || {};
    return [deviceLabel(d), d.ip, d.mac, d.vendor, d.hostname, info.model, info.type_label, info.manufacturer]
      .some((v) => v && String(v).toLowerCase().includes(q));
  });
  if (!shown.length) {
    return [h("div", { class: "panel empty" }, h("b", {}, T("Nessun dispositivo corrisponde", "No device matches")),
      T("Prova a cambiare ricerca o filtri.", "Try changing the search or the filters."))];
  }
  const online = shown.filter((d) => d.online), offline = shown.filter((d) => !d.online);
  const out = [];
  if (online.length) {
    out.push(h("div", { class: "group-title" }, N(online.length, "dispositivo acceso", "dispositivi accesi", "device online", "devices online")),
      h("div", { class: "panel" }, online.map(deviceRow)));
  }
  if (offline.length) {
    out.push(h("div", { class: "group-title" }, N(offline.length, "dispositivo spento", "dispositivi spenti", "device offline", "devices offline")),
      h("div", { class: "panel" }, offline.map(deviceRow)));
  }
  return out;
}

function focusSmart(id) {
  const owner = networks().find((n) => n.devices.some((d) => d.id === id));
  if (owner) section = owner.key;
  devQuery = ""; smartFilter = "all";
  go("devices", "s:" + id);
}

function smartRow(d) {
  const findings = smartFindings(d.id);
  const signal = d.lqi != null ? `LQI ${Math.round(d.lqi)}` : d.rssi != null ? `${Math.round(d.rssi)} dBm` : "";
  const facts = [
    [T("Produttore", "Vendor"), d.manufacturer], [T("Modello", "Model"), d.model], [T("Area", "Area"), d.area],
    [T("Integrazioni", "Integrations"), (d.integrations || []).join(", ")],
    [T("Batteria", "Battery"), d.battery != null ? `${Math.round(d.battery)}%` : d.battery_low ? T("scarica", "low") : ""],
    [T("Segnale", "Signal"), signal],
    [T("Ultima comunicazione", "Last report"), d.seen ? fmt(d.seen) : ""],
    [T("Entità", "Entities"), d.entities],
    [T("Visto la prima volta", "First seen"), fmt(d.first_seen)],
  ].filter((x) => x[1]);
  const down = d.offline || d.silent;
  return row("s:" + d.id, d.offline ? "dim" : "", [
    h("span", { class: "type-icon" + (d.offline ? " off" : "") }, icon(d.network)),
    h("span", { class: "main" }, h("div", { class: "title" }, d.name),
      h("div", { class: "sub" }, [d.model, d.area].filter(Boolean).join(", ") || d.manufacturer || "")),
    h("span", { class: "tags" },
      d.offline ? h("span", { class: "pill high" }, T("Non risponde", "Not responding")) : null,
      d.silent ? h("span", { class: "pill medium" }, T("Non comunica", "Not reporting")) : null,
      d.battery != null ? h("span", { class: "pill " + (d.battery_low ? (d.battery <= 5 ? "critical" : "medium") : "plain") },
        `${Math.round(d.battery)}%`) : d.battery_low ? h("span", { class: "pill medium" }, T("Batteria", "Battery")) : null,
      d.weak ? h("span", { class: "pill low optional" }, T("Segnale debole", "Weak signal")) : null,
      d.update ? h("span", { class: "pill low optional" }, T("Aggiornamento", "Update")) : null,
      d.bridge ? h("span", { class: "pill plain optional" }, T("Coordinatore", "Coordinator")) : null,
      h("i", { class: "status-dot" + (down ? "" : " on"), title: down ? T("Non comunica", "Not communicating") : T("Funziona", "Working") })),
  ], [
    h("div", { class: "actions" },
      // Il pannello è in un iframe: il collegamento apre la pagina del dispositivo nella finestra principale.
      h("a", { class: "btn small", href: "/config/devices/device/" + encodeURIComponent(d.id), target: "_top" },
        T("Apri in Home Assistant", "Open in Home Assistant")),
      findings.map((f) => h("button", { class: "btn small", onclick: () => go("findings", "f:" + f.id) },
        h("span", { class: "pill " + f.severity }, sevLabel(f.severity)), f.title))),
    factList(facts),
  ]);
}

function smartList(net) {
  const q = devQuery.trim().toLowerCase();
  const shown = net.devices.filter((d) => {
    if (smartFilter === "issues" && !smartFindings(d.id).length) return false;
    if (smartFilter === "battery" && !d.battery_low) return false;
    if (smartFilter === "down" && !(d.offline || d.silent)) return false;
    return !q || [d.name, d.model, d.manufacturer, d.area].some((v) => v && String(v).toLowerCase().includes(q));
  });
  if (!shown.length) {
    return [h("div", { class: "panel empty" }, h("b", {}, T("Nessun dispositivo corrisponde", "No device matches")),
      T("Prova a cambiare ricerca o filtri.", "Try changing the search or the filters."))];
  }
  return [h("div", { class: "group-title" }, N(shown.length, "dispositivo", "dispositivi", "device", "devices")),
    h("div", { class: "panel" }, shown.map(smartRow))];
}

function renderSmartDevices(net) {
  if (!net.devices.length) {
    return [h("div", { class: "panel empty" }, h("b", {}, T(`Nessun dispositivo ${net.label}`, `No ${net.label} devices`)),
      T("Compaiono qui quando Home Assistant ne conosce almeno uno.", "They show up here once Home Assistant knows at least one."))];
  }
  const list = h("div", {}, smartList(net));
  const search = h("input", { type: "search", value: devQuery, "aria-label": T("Cerca un dispositivo", "Search for a device"),
    placeholder: T("Cerca per nome, modello, area", "Search by name, model, area") });
  search.addEventListener("input", () => { devQuery = search.value; list.replaceChildren(...smartList(net)); });
  const chip = (id, text) => h("button", { class: "chip", "aria-pressed": String(smartFilter === id),
    onclick: () => { smartFilter = id; render(); } }, text);
  return [
    h("div", { class: "toolbar" }, search),
    h("div", { class: "toolbar chips" }, chip("all", T("Tutti", "All")), chip("issues", T("Con problemi", "With findings")),
      chip("down", T("Non comunicano", "Not communicating")), chip("battery", T("Batteria scarica", "Low battery"))),
    list,
  ];
}

function renderAttempts(a) {
  if (!a.sources.length) {
    return [h("div", { class: "panel empty" }, h("b", {}, T("Nessun tentativo nelle ultime 24 ore", "No attempts in the last 24 hours")),
      a.read_at ? T("Qui compaiono gli indirizzi da cui arrivano richieste con credenziali non valide.",
        "Addresses sending requests with invalid credentials appear here.")
        : (a.error || T("Il log di Home Assistant non è ancora stato letto.", "The Home Assistant log has not been read yet.")))];
  }
  return [h("div", { class: "group-title" }, N(a.sources.length, "indirizzo di provenienza", "indirizzi di provenienza", "source address", "source addresses")),
    h("div", { class: "panel" }, a.sources.map((x) => {
      const dev = state.devices.find((d) => d.ip === x.ip);
      return row("a:" + x.ip, "", [
        h("span", { class: "sev-mark " + (x.banned || x.count >= 5 || x.external ? "high" : "medium") }, icon("access")),
        h("span", { class: "main" }, h("div", { class: "title" }, x.device ? `${x.device} (${x.ip})` : x.ip),
          h("div", { class: "sub" }, (x.external ? T("da Internet", "from the Internet") : T("dalla rete locale", "from the local network")) +
            (x.host && x.host !== x.ip ? ", " + x.host : ""))),
        h("span", { class: "tags" },
          x.banned ? h("span", { class: "pill critical" }, T("Bloccato", "Banned")) : null,
          h("span", { class: "pill " + (x.count >= 5 ? "high" : "medium") }, N(x.count, "tentativo", "tentativi", "attempt", "attempts"))),
      ], [
        factList([
          [T("Ultimo tentativo", "Latest attempt"), x.last || fmt(x.last_seen)],
          [T("Indirizzi richiesti", "Requested URLs"), x.urls.join(", ")],
          [T("Client", "Client"), x.agents.join(" | ")],
        ].filter((f) => f[1])),
        dev ? h("div", { class: "actions" },
          h("button", { class: "btn small", onclick: () => focusDevice(dev.key) }, T("Vedi il dispositivo", "View the device"))) : null,
      ]);
    }))];
}

function renderDevices() {
  const net = currentNet();
  if (net && net.access) return renderAttempts(net.access);
  if (net) return renderSmartDevices(net);
  if (!state.devices.length) {
    return [h("div", { class: "panel empty" }, h("b", {}, T("Ancora nessun dispositivo", "No devices yet")),
      T("Avvia una scansione per vedere cosa è collegato alla rete.", "Start a scan to see what is connected to the network."))];
  }
  const list = h("div", {}, deviceList());
  const search = h("input", { type: "search", value: devQuery, "aria-label": T("Cerca un dispositivo", "Search for a device"),
    placeholder: T("Cerca per nome, indirizzo, produttore", "Search by name, address, vendor") });
  // Solo l'elenco viene ricostruito mentre si scrive, così il campo non perde il cursore.
  search.addEventListener("input", () => { devQuery = search.value; list.replaceChildren(...deviceList()); });
  const types = [...new Set(state.devices.map((d) => (d.is_gateway ? "router" : (d.info && d.info.type) || "sconosciuto")))].sort();
  const typeSelect = h("select", { "aria-label": T("Filtra per tipo", "Filter by type"),
    onchange: (e) => { devType = e.target.value; render(); } },
    [["", T("Tutti i tipi", "All types")], ...types.map((t) => [t, (state.types || {})[t] || t])]
      .map(([v, text]) => h("option", { value: v }, text)));
  typeSelect.value = devType;
  const chip = (id, text) => h("button", { class: "chip", "aria-pressed": String(devFilter === id),
    onclick: () => { devFilter = id; render(); } }, text);
  return [
    h("div", { class: "toolbar" }, search, typeSelect),
    h("div", { class: "toolbar chips" },
      chip("all", T("Tutti", "All")), chip("new", T("Da classificare", "To classify")),
      chip("issues", T("Con problemi", "With findings")), chip("linked", T("In domotica", "In smart home")),
      chip("unlinked", T("Fuori dalla domotica", "Not in smart home"))),
    list,
  ];
}

// ---------------------------------------------------------------- router

function renderRouter() {
  const r = state.router || {};
  const out = [];
  out.push(h("div", { class: "panel pad" },
    h("h2", {}, T("Cosa vedo del router", "What I can see of the router")),
    factList([
      [T("Indirizzo", "Address"), r.gateway || T("non rilevato", "not detected")],
      [T("Modello dichiarato", "Declared model"), r.model || "-"],
      ["UPnP", r.available ? T("attivo", "enabled") : T("non rilevato (spento o non supportato)", "not detected (off or unsupported)")],
      [T("Indirizzo pubblico", "Public address"), (r.external_ip || "-") + (r.behind_nat ? T(" (dietro il NAT dell'operatore)", " (behind your ISP's NAT)") : "")],
    ])));

  const maps = r.mappings || [];
  out.push(h("div", { class: "panel pad" },
    h("h2", {}, T("Porte aperte verso Internet", "Ports open to the Internet")),
    maps.length ? h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, [T("Porta esterna", "External port"), T("Verso", "To"), T("Descrizione", "Description")]
        .map((t) => h("th", {}, t)))),
      h("tbody", {}, maps.map((m) => {
        const dev = state.devices.find((d) => d.ip === m.internal_client);
        return h("tr", {},
          h("td", {}, `${m.external_port}/${m.protocol}`),
          h("td", {}, `${dev ? deviceLabel(dev) + ", " : ""}${m.internal_client}:${m.internal_port}`),
          h("td", {}, m.description || "-"));
      }))))
      : h("p", { class: "muted" }, r.available ? T("Nessuna apertura attiva.", "No active forwards.")
        : T("UPnP non risponde: da qui non si può leggere nessuna apertura.", "UPnP does not answer: no forward can be read from here.")),
    h("p", { class: "small muted" }, T(
      "Compaiono solo le aperture create via UPnP, che puoi chiudere dalla scheda Problemi. I port forwarding inseriti a mano si vedono solo nel pannello del router.",
      "Only forwards created through UPnP appear here, and you can close them from the Findings tab. Manually configured port forwards are visible only in the router's panel."))));

  const done = state.checklist.filter((i) => i.done).length;
  const bar = h("i", {});
  bar.style.width = `${Math.round(100 * done / Math.max(1, state.checklist.length))}%`;
  const panel = r.gateway ? ` (http://${r.gateway})` : "";
  out.push(h("div", { class: "panel pad" },
    h("h2", {}, T(`Verifiche da fare a mano: ${done} di ${state.checklist.length}`, `Checks to do by hand: ${done} of ${state.checklist.length}`)),
    h("div", { class: "progress" }, bar),
    h("p", { class: "small muted" }, T(
      `Queste impostazioni non si leggono dalla rete: aprile dal pannello del router${panel} e spunta ciò che hai verificato. I nomi dei menu possono variare.`,
      `These settings cannot be read from the network: open them in the router's panel${panel} and tick what you have verified. Menu names may vary.`)),
    state.checklist.map((item) => h("div", { class: "check" + (item.done ? " done" : "") },
      h("input", { type: "checkbox", checked: item.done, id: "chk-" + item.id,
        onchange: (e) => act("api/checklist", { id: item.id, done: e.target.checked }) }),
      h("div", {},
        h("label", { for: "chk-" + item.id }, h("b", {}, item.title)),
        item.done ? null : [h("div", { class: "small muted" }, item.why), h("div", { class: "small" }, item.how)])))));
  return out;
}

// ---------------------------------------------------------------- stato e cronologia

function renderHistory() {
  const ha = state.ha || {};
  const links = ha.links || {};
  const channels = { mqtt: "MQTT", api: T("API di Home Assistant", "Home Assistant API"), none: T("Nessuno", "None") };
  const facts = [
    [T("Canale", "Channel"), channels[ha.channel] || ha.channel || "-"],
    [T("Dettaglio", "Detail"), ha.detail || "-"],
    [T("Entità pubblicate", "Published entities"), ha.entities || 0],
    [T("Ultimo invio riuscito", "Last successful publish"), fmt(ha.last_ok)],
    [T("Registro della domotica", "Smart home registry"), links.ok
      ? T(`letto, ${links.devices} dispositivi di Home Assistant`, `read, ${links.devices} Home Assistant devices`)
      : (links.error || T("non ancora letto", "not read yet"))],
  ];
  if (ha.error) facts.push([T("Errore", "Error"), ha.error]);
  if (ha.channel !== "mqtt" && ha.mqtt_reason) facts.push([T("Perché non MQTT", "Why not MQTT"), ha.mqtt_reason]);
  const healthy = !ha.error && ha.channel !== "none";
  const out = [h("div", { class: "panel pad" },
    h("h2", {}, T("Sensori verso Home Assistant", "Sensors to Home Assistant"), " ",
      h("span", { class: "pill " + (healthy ? "okc" : "high") }, healthy ? T("Funziona", "Working") : T("Da controllare", "Needs checking"))),
    factList(facts))];
  if (!state.scans.length) return out;
  const heads = [T("Scansione", "Scan"), T("Durata", "Duration"), T("Dispositivi", "Devices"),
    T("Critici e alti", "Critical and high"), T("Medi", "Medium"), T("Bassi e info", "Low and info")];
  out.push(h("div", { class: "panel pad" },
    h("h2", {}, T("Ultime scansioni", "Recent scans")),
    h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, heads.map((t) => h("th", {}, t)))),
      h("tbody", {}, [...state.scans].reverse().map((x) => h("tr", {},
        h("td", {}, fmt(x.ts)), h("td", {}, x.duration + " s"), h("td", {}, x.devices),
        h("td", {}, x.counts.critical + x.counts.high), h("td", {}, x.counts.medium),
        h("td", {}, x.counts.low + x.counts.info))))))));
  return out;
}

// ---------------------------------------------------------------- ciclo principale

const VIEWS = { findings: renderFindings, incidents: renderIncidents, devices: renderDevices,
  router: renderRouter, history: renderHistory };

function renderSections() {
  const alertFor = (key) => state.findings.some((f) => netOf(f) === key && f.status === "open" && SEV_RANK[f.severity] <= 2)
    || state.incidents.some((i) => netOf(i) === key && !i.acknowledged);
  const items = [["lan", T("Rete locale", "Local network"), state.devices.filter((d) => d.online).length],
    ...networks().map((n) => [n.key, n.label, n.summary.total])];
  if (state.access) items.push(["access", T("Accessi", "Access"), state.access.sources.length]);
  $("sections").replaceChildren(...items.map(([key, label, count]) =>
    h("button", { class: "section" + (count ? "" : " none"), "aria-pressed": String(section === key),
      onclick: () => { section = key; tab = "findings"; devQuery = ""; render(); } },
      icon(key), h("span", {}, label),
      count ? h("span", { class: "count" + (alertFor(key) ? " alert" : "") }, count) : null)));
}

function renderTabs() {
  const open = secFindings().filter((f) => f.status === "open");
  const grave = open.some((f) => SEV_RANK[f.severity] <= 1);
  const pending = secIncidents().filter((i) => !i.acknowledged).length;
  const done = state.checklist.filter((i) => i.done).length;
  const net = currentNet();
  const tabs = [
    ["findings", T("Problemi", "Findings"), open.length, grave],
    ["incidents", T("Incidenti", "Incidents"), pending, pending > 0],
    net && net.access ? ["devices", T("Tentativi", "Attempts"), net.access.attempts_24h, false]
      : ["devices", T("Dispositivi", "Devices"), net ? net.summary.total : state.devices.filter((d) => d.online).length, false],
  ];
  if (!net) tabs.push(["router", "Router", `${done}/${state.checklist.length}`, false], ["history", T("Stato", "Status"), null, false]);
  if (!tabs.some(([id]) => id === tab)) tab = "findings";
  document.querySelector(".tabs").replaceChildren(...tabs.map(([id, text, count, alert]) =>
    h("button", { role: "tab", "aria-selected": String(tab === id), onclick: () => { tab = id; render(); } },
      text, count === null || count === 0 ? null : h("span", { class: "count" + (alert ? " alert" : "") }, count))));
}

function render() {
  if (!state) return;
  if (section !== "lan" && !currentNet()) section = "lan";  // sezione spenta dalle opzioni
  renderSections();
  renderHero();
  renderTabs();
  $("view").replaceChildren(...VIEWS[tab]());
}

async function refresh(force) {
  try {
    const next = await api("api/state");
    const json = JSON.stringify(next);
    const active = document.activeElement;
    const typing = active && active.matches("input[type=text], input[type=search], select");
    if (!force && (json === lastJson || typing || $("confirm").open)) return;
    LANG = next.lang === "it" ? "it" : "en";
    document.documentElement.lang = LANG;
    state = next;
    lastJson = json;
    render();
  } catch (err) {
    if (!state) $("hero").replaceChildren(h("p", { class: "muted" }, T("Impossibile leggere lo stato: ", "Cannot read the status: ") + err.message));
  }
}

$("scan").addEventListener("click", startScan);
refresh(true);
setInterval(refresh, 4000);
