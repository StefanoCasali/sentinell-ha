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

const SEV = { critical: "Critico", high: "Alto", medium: "Medio", low: "Basso", info: "Info" };
const $ = (id) => document.getElementById(id);
const fmt = (ts) => ts ? new Date(ts * 1000).toLocaleString("it-IT", { dateStyle: "short", timeStyle: "short" }) : "-";

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
  if (!res.ok) throw new Error(data.error || `Errore ${res.status}`);
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

// ---------------------------------------------------------------- riepilogo

function renderSummary() {
  const c = state.counts;
  const online = state.devices.filter((d) => d.online);
  const pending = state.incidents.filter((i) => !i.acknowledged).length;
  const tiles = [
    [state.score, "Punteggio su 100", state.score >= 80 ? "okc" : state.score >= 50 ? "medium" : "high"],
    [pending, "Incidenti da verificare", pending ? "high" : "okc"],
    [c.critical + c.high, "Critici e alti", c.critical + c.high ? "high" : "okc"],
    [c.medium, "Medi", c.medium ? "medium" : "okc"],
    [c.low + c.info, "Bassi e informativi", "info"],
    [online.length, "Dispositivi accesi", "info"],
    [online.filter((d) => !d.trusted).length, "Da classificare", "info"],
  ];
  $("summary").replaceChildren(...tiles.map(([n, label, cls]) =>
    h("div", { class: "tile " + cls }, h("b", { style: null, class: "badge-num" }, n), h("span", {}, label))));

  const last = state.scans[state.scans.length - 1];
  const s = state.status;
  $("scan").disabled = s.running;
  $("scan").textContent = s.running ? (s.phase || "Scansione in corso") + "..." : "Avvia scansione";
  $("subtitle").textContent = last
    ? `Ultima scansione: ${fmt(last.ts)} su ${state.networks.join(", ") || "rete locale"}` +
      (s.next_scan ? ` - prossima: ${fmt(s.next_scan)}` : "")
    : "Nessuna scansione ancora eseguita";
  if (s.error) banner("Ultima scansione non riuscita: " + s.error, "error");
}

// ---------------------------------------------------------------- problemi

function findingCard(f) {
  const dev = state.devices.find((d) => d.key === f.device_key);
  const where = dev ? `${deviceLabel(dev)} (${dev.ip})${f.port && f.category !== "router" ? " - porta " + f.port : ""}`
    : (f.category === "router" ? "Router" : f.ip || "");
  const closed = f.status !== "open";
  const buttons = [];
  if (f.status === "open") {
    if (f.action) {
      buttons.push(h("button", { class: "danger small", onclick: async () => {
        const ok = await confirmDialog(f.action.label + "?",
          `Verrà chiesto al router di chiudere la porta ${f.action.external_port}/${f.action.protocol}. ` +
          "Il servizio che la usa non sarà più raggiungibile da Internet.");
        if (ok) act("api/action", { id: f.id, confirm: true });
      } }, f.action.label));
    }
    if (f.id.startsWith("new-device:")) {
      buttons.push(h("button", { class: "small", onclick: () => act("api/device", { key: f.device_key, trusted: true }) },
        "Lo riconosco: fidato"));
    }
    buttons.push(h("button", { class: "small", onclick: () => act("api/finding", { id: f.id, status: "ignored" }) },
      "Ignora"));
  } else if (f.status === "ignored") {
    buttons.push(h("button", { class: "small", onclick: () => act("api/finding", { id: f.id, status: "open" }) },
      "Riapri"));
  }
  const details = h("details", { open: openDetails.has(f.id) },
    h("summary", {}, "Come rimediare"),
    h("ol", { class: "steps" }, f.remediation.map((step) => h("li", {}, step))));
  details.addEventListener("toggle", () => details.open ? openDetails.add(f.id) : openDetails.delete(f.id));
  return h("div", { class: `card sev ${closed ? "info" : f.severity}` },
    h("div", { class: "row" },
      h("span", { class: "badge " + f.severity }, SEV[f.severity]),
      h("h3", { class: "grow" }, f.title),
      closed ? h("span", { class: "badge" }, f.status === "ignored" ? "Ignorato" : "Risolto") : null),
    h("div", { class: "muted" }, `${where} - rilevato il ${fmt(f.first_seen)}`),
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
      ` Mostra anche ignorati e risolti (${closed.length})`))];
  if (!open.length) {
    out.push(h("div", { class: "card empty" }, state.scans.length
      ? "Nessun problema aperto. Controlla anche la scheda Router per le verifiche manuali."
      : "Avvia la prima scansione per controllare la rete."));
  }
  out.push(...open.map(findingCard));
  if (showClosed) out.push(...closed.map(findingCard));
  return out;
}

// ---------------------------------------------------------------- incidenti

function renderIncidents() {
  if (!state.incidents.length) {
    return [h("div", { class: "card empty" },
      "Nessun incidente. Qui compaiono i cambiamenti sospetti tra una scansione e l'altra: nuovi dispositivi, nuove porte, nuove aperture verso Internet.")];
  }
  const pending = state.incidents.filter((i) => !i.acknowledged);
  const out = [];
  if (pending.length > 1) {
    out.push(h("div", { class: "actions filter" },
      h("button", { class: "small", onclick: () => act("api/incident", { all: true }) },
        `Segna tutti come verificati (${pending.length})`)));
  }
  out.push(...state.incidents.map((i) => h("div", { class: `card sev ${i.acknowledged ? "info" : i.severity}` },
    h("div", { class: "row" },
      h("span", { class: "badge " + i.severity }, SEV[i.severity]),
      h("h3", { class: "grow" }, i.title),
      i.acknowledged ? h("span", { class: "badge" }, "Verificato") : null),
    h("div", { class: "muted" }, fmt(i.ts) + (i.device ? ` - ${i.device}${i.ip ? " (" + i.ip + ")" : ""}` : "")),
    h("p", {}, i.detail),
    i.acknowledged ? null : h("div", { class: "actions" },
      h("button", { class: "small", onclick: () => act("api/incident", { id: i.id }) }, "Ho verificato")))));
  return out;
}

// ---------------------------------------------------------------- dispositivi

function deviceCard(d) {
  const nameInput = h("input", { type: "text", value: d.name || "", placeholder: "Dai un nome (es. TV salotto)",
    "aria-label": "Nome del dispositivo" });
  nameInput.addEventListener("change", () => act("api/device", { key: d.key, name: nameInput.value }));
  const tags = [
    d.is_gateway ? h("span", { class: "badge" }, "Router") : null,
    d.is_self ? h("span", { class: "badge" }, "Questo host") : null,
    d.online ? null : h("span", { class: "badge" }, "Spento"),
    d.trusted ? h("span", { class: "badge okc" }, "Fidato") : h("span", { class: "badge medium" }, "Da classificare"),
  ];
  const problems = state.findings.filter((f) => f.device_key === d.key && f.status === "open").length;
  const info = d.info || {};
  if (info.type_label && !d.is_gateway) tags.unshift(h("span", { class: "badge low" }, info.type_label));
  const facts = [
    ["Modello", [info.manufacturer, info.model].filter(Boolean).join(" ")],
    ["Nome annunciato", info.friendly_name],
    ["Sistema operativo", info.os ? `${info.os} (stima ${info.os_accuracy || "?"}%)` : ""],
    ["Firmware", info.firmware],
    ["Nome Windows", [info.netbios, info.workgroup].filter(Boolean).join(" - gruppo ")],
    ["Servizi annunciati", (info.services || []).join(", ")],
    ["MAC", info.private_mac ? "casuale (privato): può cambiare e far ricomparire il dispositivo come nuovo" : ""],
    ["Fonti", (info.sources || []).join(", ")],
  ].filter(([, v]) => v);
  return h("div", { class: "card" },
    h("div", { class: "row" },
      h("h3", { class: "grow" }, deviceLabel(d)), tags),
    h("div", { class: "muted" },
      [d.ip, d.mac, d.vendor, d.hostname].filter(Boolean).join(" - ") +
      ` - visto la prima volta il ${fmt(d.first_seen)}` + (problems ? ` - ${problems} problemi aperti` : "")),
    facts.length ? h("div", { class: "facts" }, facts.map(([k, v]) =>
      h("div", {}, h("span", { class: "muted" }, k + ": "), v))) : null,
    haLinks(d),
    d.ports && d.ports.length ? h("div", { class: "ports" }, d.ports.map((p) => {
      const cert = p.info.cert_subject
        ? ` | certificato: ${p.info.cert_subject}${p.info.cert_self_signed ? " (autofirmato)" : ""}` +
          (p.info.cert_expires ? `, scade il ${fmt(p.info.cert_expires)}` : "") : "";
      const extra = [p.info.product, p.info.title || p.info.server || p.info.banner].filter(Boolean).join(" | ") + cert;
      return h("span", { class: "port" + (p.info.cert_expired ? " expired" : ""), title: extra },
        `${p.port} ${p.service}${p.info.product ? " · " + p.info.product : ""}`);
    })) : h("div", { class: "muted" }, "Nessuna porta aperta tra quelle controllate."),
    h("div", { class: "actions" },
      nameInput,
      h("button", { class: "small", onclick: () => act("api/device", { key: d.key, trusted: !d.trusted }) },
        d.trusted ? "Togli da fidati" : "Segna come fidato"),
      d.online ? null : h("button", { class: "small", onclick: async () => {
        if (await confirmDialog("Dimenticare il dispositivo?",
          "Verrà rimosso dall'elenco insieme ai suoi problemi. Se si ricollega, sarà segnalato come nuovo."))
          act("api/device/forget", { key: d.key });
      } }, "Dimentica")));
}

function haLinks(d) {
  const link = d.ha;
  if (!link) return null;
  if (!link.linked) {
    return h("div", { class: "halink muted" }, "Domotica: non collegato a nessuna integrazione di Home Assistant.");
  }
  const rows = link.devices.map((x) => h("div", {},
    h("b", {}, "In Home Assistant: "),
    // Il pannello è in un iframe: il collegamento apre la pagina del dispositivo nella finestra principale.
    h("a", { href: "/config/devices/device/" + encodeURIComponent(x.id), target: "_top" }, x.name || x.id),
    [x.manufacturer, x.model].filter(Boolean).length ? ` (${[x.manufacturer, x.model].filter(Boolean).join(" ")})` : "",
    x.integrations.length ? ` - integrazioni: ${x.integrations.join(", ")}` : "",
    x.area ? ` - area: ${x.area}` : "",
    h("span", { class: "muted" }, ` - riconosciuto per ${x.match.join(", ")}`),
    x.entity_count ? h("details", {},
      h("summary", {}, `${x.entity_count} entità`),
      h("div", { class: "ports" }, x.entities.map((e) => h("span", { class: "port" }, e)),
        x.entity_count > x.entities.length ? h("span", { class: "muted" }, "...") : null)) : null));
  if (link.entities.length) {
    rows.push(h("div", {}, h("b", {}, "Entità che lo citano: "),
      h("span", { class: "ports" }, link.entities.map((e) =>
        h("span", { class: "port", title: `${e.name} - ${e.match}` }, e.entity_id)))));
  }
  return h("div", { class: "halink" }, rows);
}

let typeFilter = "";
let haFilter = "";

function renderDevices() {
  if (!state.devices.length) return [h("div", { class: "card empty" }, "Nessun dispositivo: avvia una scansione.")];
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
      select(typeFilter, [["", "Tutti i tipi"], ...present.map((t) => [t, (state.types || {})[t] || t])],
        (v) => { typeFilter = v; }, "Filtra per tipo"),
      select(haFilter, [["", "Domotica: tutti"], ["si", "Collegati a Home Assistant"], ["no", "Non collegati"]],
        (v) => { haFilter = v; }, "Filtra per collegamento alla domotica"),
      h("span", {}, `${shown.length} di ${state.devices.length} dispositivi`)),
    ...shown.map(deviceCard),
  ];
}

// ---------------------------------------------------------------- router

function renderRouter() {
  const r = state.router || {};
  const out = [];
  const facts = [
    ["Indirizzo del router", r.gateway || "non rilevato"],
    ["Modello dichiarato", r.model || "-"],
    ["UPnP", r.available ? "attivo" : "non rilevato (spento o non supportato)"],
    ["Indirizzo pubblico (WAN)", r.external_ip || "-"],
  ];
  out.push(h("div", { class: "card" },
    h("h2", {}, "Stato rilevato"),
    h("div", { class: "table-wrap" }, h("table", {}, h("tbody", {},
      facts.map(([k, v]) => h("tr", {}, h("th", {}, k), h("td", {}, v))))))));

  const maps = r.mappings || [];
  out.push(h("div", { class: "card" },
    h("h2", {}, "Porte aperte verso Internet via UPnP"),
    maps.length ? h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, ["Porta esterna", "Verso", "Descrizione"].map((t) => h("th", {}, t)))),
      h("tbody", {}, maps.map((m) => {
        const dev = state.devices.find((d) => d.ip === m.internal_client);
        return h("tr", {},
          h("td", {}, `${m.external_port}/${m.protocol}`),
          h("td", {}, `${dev ? deviceLabel(dev) + " - " : ""}${m.internal_client}:${m.internal_port}`),
          h("td", {}, m.description || "-"));
      }))))
      : h("p", { class: "muted" }, r.available ? "Nessuna apertura attiva." : "UPnP non risponde: nessuna apertura leggibile da qui."),
    h("p", { class: "muted" },
      "Qui compaiono solo le aperture create via UPnP. I port forwarding inseriti a mano si vedono solo nel pannello del router: usa la lista qui sotto. Per chiudere un'apertura UPnP usa il pulsante nella scheda Problemi.")));

  const done = state.checklist.filter((i) => i.done).length;
  out.push(h("div", { class: "card" },
    h("h2", {}, `Verifiche manuali sul router (${done}/${state.checklist.length})`),
    h("p", { class: "muted" },
      `Queste impostazioni non sono leggibili dalla rete: aprile dal pannello del router${r.gateway ? " (http://" + r.gateway + ")" : ""} e spunta ciò che hai verificato. I nomi dei menu possono variare con il firmware dell'operatore.`),
    state.checklist.map((item) => h("div", { class: "card check" },
      h("input", { type: "checkbox", checked: item.done, id: "chk-" + item.id,
        onchange: (e) => act("api/checklist", { id: item.id, done: e.target.checked }) }),
      h("div", {},
        h("label", { for: "chk-" + item.id }, h("b", {}, item.title)),
        h("div", { class: "muted" }, item.why),
        h("div", {}, item.how))))));
  return out;
}

// ---------------------------------------------------------------- cronologia

const CHANNELS = { mqtt: "MQTT", api: "API di Home Assistant", nessuno: "Nessuno" };

function haCard() {
  const ha = state.ha || {};
  const facts = [
    ["Canale", CHANNELS[ha.channel] || ha.channel || "-"],
    ["Dettaglio", ha.detail || "-"],
    ["Entità pubblicate", ha.entities || 0],
    ["Ultimo invio riuscito", fmt(ha.last_ok)],
  ];
  if (ha.error) facts.push(["Errore", ha.error]);
  if (ha.channel !== "mqtt" && ha.mqtt_reason) facts.push(["Perché non MQTT", ha.mqtt_reason]);
  const links = ha.links || {};
  facts.push(["Registro della domotica", links.ok ? `letto, ${links.devices} dispositivi di Home Assistant`
    : (links.error || "non ancora letto")]);
  return h("div", { class: "card sev " + (ha.error || ha.channel === "nessuno" ? "high" : "okc") },
    h("h2", {}, "Sensori verso Home Assistant"),
    h("div", { class: "table-wrap" }, h("table", {}, h("tbody", {},
      facts.map(([k, v]) => h("tr", {}, h("th", {}, k), h("td", {}, v)))))));
}

function renderHistory() {
  if (!state.scans.length) return [haCard(), h("div", { class: "card empty" }, "Nessuna scansione eseguita.")];
  return [haCard(), h("div", { class: "card table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, ["Data", "Durata", "Dispositivi", "Critici/alti", "Medi", "Bassi/info"].map((t) => h("th", {}, t)))),
    h("tbody", {}, [...state.scans].reverse().map((s) => h("tr", {},
      h("td", {}, fmt(s.ts)), h("td", {}, s.duration + " s"), h("td", {}, s.devices),
      h("td", {}, s.counts.critical + s.counts.high), h("td", {}, s.counts.medium),
      h("td", {}, s.counts.low + s.counts.info))))))];
}

// ---------------------------------------------------------------- ciclo principale

const VIEWS = { findings: renderFindings, incidents: renderIncidents, devices: renderDevices, router: renderRouter, history: renderHistory };

function render() {
  if (!state) return;
  renderSummary();
  $("view").replaceChildren(...VIEWS[tab]());
}

async function refresh(force) {
  try {
    const next = await api("api/state");
    const json = JSON.stringify(next);
    const typing = document.activeElement && document.activeElement.matches("input[type=text]");
    if (!force && (json === lastJson || typing || $("confirm").open)) return;
    state = next;
    lastJson = json;
    render();
  } catch (err) {
    banner("Impossibile leggere lo stato: " + err.message, "error");
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
