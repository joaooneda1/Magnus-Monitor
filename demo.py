#!/usr/bin/env python3
"""
Magnus Monitor - modo demonstração.

Serve o mesmo painel (static/index.html) com ramais e clientes FICTÍCIOS,
sem conectar em Asterisk nem na API do MagnusBilling. Serve para prints e
apresentações sem expor dados reais.

    python demo.py            # http://localhost:8088
"""
import json
import os
import random
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PORT = int(os.environ.get("DASH_PORT", "8088"))
TITLE = os.environ.get("PANEL_TITLE", "Ramais")

CLIENTES = [
    "Padaria Pão Dourado", "Clínica Vida Plena", "Auto Peças Rodovia", "Escritório Contábil Alfa",
    "Farmácia Bem Estar", "Imobiliária Horizonte", "Pet Shop Amigo Fiel", "Restaurante Sabor Caseiro",
    "Academia Movimento", "Ótica Visão Clara", "Mercado Bom Preço", "Advocacia Souza & Lima",
    "Hotel Serra Azul", "Construtora Pilar", "Escola Aprender", "Distribuidora Norte",
    "Laboratório Diagnóstico", "Transportadora Rápida", "Loja Casa & Cia", "Consultório Odonto Sorriso",
    "Gráfica Impressão Já", "Oficina Motor Forte", "Buffet Festa Boa", "Papelaria Estrela",
]
AGENTES = ["Yealink SIP-T31P", "Grandstream GXP1610", "Zoiper 5", "MicroSIP 3.21", "Intelbras TIP 125"]

random.seed(7)
START = time.time()
RAMAIS = []
for i, cli in enumerate(CLIENTES):
    for j in range(random.choice([1, 1, 2, 3])):
        ext = str(1001 + i * 10 + j)
        RAMAIS.append({
            "ext": ext, "client": cli,
            "callerid": "11" + str(30000000 + random.randint(0, 9999999)),
            # Faixas reservadas para documentação (RFC 5737): nunca são IPs reais.
            "ip": random.choice(["203.0.113.", "198.51.100.", "192.0.2."]) + str(random.randint(2, 250)),
            "rtt_ms": random.randint(8, 70),
            "user_agent": random.choice(AGENTES),
            "status": "online", "in_call": False, "alerted": False,
            "since": START - random.randint(3600, 5 * 86400), "last_seen": START,
        })

# Alguns offline (um recente, ainda na carência; outros já alertados) e alguns em ligação.
for r, ago, alerted in [(RAMAIS[3], 45, False), (RAMAIS[11], 1260, True), (RAMAIS[19], 7400, True)]:
    r.update(status="offline", since=START - ago, alerted=alerted, rtt_ms=None, last_seen=START - ago)
for r in random.sample([r for r in RAMAIS if r["status"] == "online"], 5):
    r["in_call"] = True

EVENTOS = []
t = START
for _ in range(60):
    t -= random.randint(600, 5400)
    r = random.choice(RAMAIS)
    fora = random.randint(95, 2400)
    EVENTOS.append({"ts": t, "ext": r["ext"], "from": "offline", "to": "online", "duration": fora})
    EVENTOS.append({"ts": t - fora, "ext": r["ext"], "from": "online", "to": "offline",
                    "duration": random.randint(3600, 3 * 86400)})
for r in RAMAIS:
    if r["status"] == "offline" and r["alerted"]:
        EVENTOS.append({"ts": r["since"], "ext": r["ext"], "from": "online", "to": "offline", "duration": 86400})
EVENTOS.sort(key=lambda e: e["ts"], reverse=True)


def snapshot():
    now = time.time()
    rows = [dict(r) for r in RAMAIS]
    for r in rows:
        if r["status"] == "online":
            r["last_seen"] = now
            r["rtt_ms"] = max(5, r["rtt_ms"] + random.randint(-4, 4))
    return {
        "now": now, "updated_at": now - random.uniform(0, 5), "error": None, "error_since": None,
        "api_error": None, "source": "ami", "driver": "pjsip", "poll": 15, "grace": 90, "title": TITLE,
        "summary": {
            "total": len(rows),
            "online": sum(r["status"] == "online" for r in rows),
            "offline": sum(r["status"] == "offline" for r in rows),
            "in_call": sum(r["in_call"] for r in rows),
        },
        "ramais": rows,
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "MagnusMonitorDemo"

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj):
        self._send(200, json.dumps(obj, ensure_ascii=False).encode(), "application/json; charset=utf-8")

    def do_GET(self):
        url = urlparse(self.path)
        if url.path in ("/", "/index.html"):
            with open(os.path.join(BASE_DIR, "static", "index.html"), "rb") as f:
                return self._send(200, f.read(), "text/html; charset=utf-8")
        if url.path == "/health":
            return self._json({"ok": True, "updated_at": time.time()})
        if url.path == "/api/status":
            return self._json(snapshot())
        if url.path == "/api/events":
            q = parse_qs(url.query)
            ext = q.get("ext", [None])[0]
            limit = int(q.get("limit", ["100"])[0])
            return self._json([e for e in EVENTOS if not ext or e["ext"] == ext][:limit])
        self._json({"error": "não encontrado"})


if __name__ == "__main__":
    print(f"Modo demonstração: {len(RAMAIS)} ramais fictícios em http://localhost:{PORT}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
