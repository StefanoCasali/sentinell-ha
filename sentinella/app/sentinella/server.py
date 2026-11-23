"""Server HTTP dell'interfaccia (servita dentro Home Assistant via ingress)."""

import json
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import __version__, config

log = logging.getLogger(__name__)

WEB = Path(__file__).parent / "web"
STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/static/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/static/style.css": ("style.css", "text/css; charset=utf-8"),
}
# Nessuno script o stile inline: i nomi e i banner dei dispositivi sono dati non fidati.
CSP = "default-src 'self'; frame-ancestors *; base-uri 'none'; form-action 'none'"


def make_handler(engine):
    class Handler(BaseHTTPRequestHandler):
        server_version = "Sentinella"

        def log_message(self, fmt, *args):
            log.debug("%s %s", self.address_string(), fmt % args)

        def _allowed(self) -> bool:
            # In produzione risponde solo al proxy ingress, che ha già autenticato l'utente.
            client = self.client_address[0]
            return client == config.INGRESS_PROXY or (config.DEV and client == "127.0.0.1")

        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Security-Policy", CSP)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, payload, code: int = 200) -> None:
            self._send(code, json.dumps(payload, ensure_ascii=False).encode(), "application/json")

        def do_GET(self):
            if not self._allowed():
                return self._json({"error": "accesso negato"}, 403)
            path = self.path.split("?", 1)[0]
            if path == "/api/state":
                return self._json({"version": __version__, **engine.snapshot()})
            if path in STATIC:
                name, ctype = STATIC[path]
                return self._send(200, (WEB / name).read_bytes(), ctype)
            self._json({"error": "non trovato"}, 404)

        def do_POST(self):
            if not self._allowed():
                return self._json({"error": "accesso negato"}, 403)
            # L'intestazione personalizzata impedisce richieste inviate da altri siti aperti nel browser.
            if self.headers.get("X-Sentinella") != "1":
                return self._json({"error": "richiesta non valida"}, 400)
            try:
                length = min(int(self.headers.get("Content-Length") or 0), 65536)
                body = json.loads(self.rfile.read(length) or b"{}")
                if not isinstance(body, dict):
                    raise ValueError
            except ValueError:
                return self._json({"error": "JSON non valido"}, 400)
            path = self.path.split("?", 1)[0]
            try:
                message = self._dispatch(path, body)
            except KeyError:
                return self._json({"error": "elemento non trovato"}, 404)
            except (RuntimeError, ValueError) as exc:
                return self._json({"error": str(exc)}, 409)
            self._json({"ok": True, "message": message})

        def _dispatch(self, path: str, body: dict):
            if path == "/api/scan":
                if not engine.start_scan():
                    raise RuntimeError("una scansione è già in corso")
                return "Scansione avviata."
            if path == "/api/finding":
                engine.set_finding_status(str(body.get("id")), str(body.get("status")))
                return None
            if path == "/api/device":
                engine.update_device(str(body.get("key")), body.get("name"), body.get("trusted"))
                return None
            if path == "/api/device/forget":
                engine.forget_device(str(body.get("key")))
                return None
            if path == "/api/incident":
                engine.acknowledge_incident(None if body.get("all") is True else str(body.get("id")))
                return None
            if path == "/api/checklist":
                engine.set_checklist(str(body.get("id")), bool(body.get("done")))
                return None
            if path == "/api/action":
                if body.get("confirm") is not True:
                    raise ValueError("conferma mancante")
                return engine.apply_action(str(body.get("id")))
            raise KeyError(path)

    return Handler


def serve(engine) -> None:
    # In sviluppo solo su loopback; nell'add-on (rete dell'host) filtra l'indirizzo del proxy ingress.
    host = "127.0.0.1" if config.DEV else "0.0.0.0"
    httpd = ThreadingHTTPServer((host, config.PORT), make_handler(engine))
    httpd.daemon_threads = True
    log.info("Interfaccia in ascolto su %s:%s", host, config.PORT)
    httpd.serve_forever()
