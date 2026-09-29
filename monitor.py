#!/usr/bin/env python3
"""
Magnus Monitor — painel de ramais online/offline com alertas.

Status em tempo real via AMI do Asterisk (PJSIP ou chan_sip) e, opcionalmente,
nomes de clientes e lista de ramais pela API do MagnusBilling.
Configuração no arquivo .env (veja .env.example).
"""
import argparse
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import socket
import sqlite3
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlparse

import requests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
log = logging.getLogger("magnus-monitor")


# --------------------------------------------------------------------------
# Configuração
# --------------------------------------------------------------------------
def load_env(path):
    if not os.path.exists(path):
        return False
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k, v = k.strip(), v.strip()
            if " #" in v:
                v = v.split(" #", 1)[0].strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                v = v[1:-1]
            os.environ.setdefault(k, v)
    return True


def env(k, d=""):
    return os.environ.get(k, d).strip()


def env_bool(k, d=False):
    v = env(k).lower()
    return d if v == "" else v in ("1", "true", "sim", "yes", "on")


def env_int(k, d):
    try:
        return int(env(k) or d)
    except ValueError:
        return d


def env_list(k):
    return [x.strip() for x in env(k).split(",") if x.strip()]


class Config:
    def __init__(self):
        self.source = env("STATUS_SOURCE", "ami").lower()          # ami | api
        self.sip_driver = env("SIP_DRIVER", "auto").lower()        # auto | pjsip | sip

        self.mb_url = env("MB_URL").rstrip("/")
        self.mb_key = env("MB_API_KEY")
        self.mb_secret = env("MB_API_SECRET")
        self.mb_verify_ssl = env_bool("MB_VERIFY_SSL", True)
        self.only_api_users = env_bool("ONLY_API_USERS", True)
        self.meta_refresh = env_int("API_REFRESH_SECONDS", 600)

        self.ami_host = env("AMI_HOST", "127.0.0.1")
        self.ami_port = env_int("AMI_PORT", 5038)
        self.ami_user = env("AMI_USER")
        self.ami_secret = env("AMI_SECRET")

        self.poll = max(5, env_int("POLL_INTERVAL", 15))
        self.grace = max(0, env_int("OFFLINE_GRACE", 90))
        self.alert_recovery = env_bool("ALERT_ON_RECOVERY", True)
        self.mass_threshold = env_int("MASS_OUTAGE_THRESHOLD", 10)
        self.watch_only = env_list("WATCH_ONLY")
        self.ignore = env_list("IGNORE")

        self.tg_token = env("TELEGRAM_BOT_TOKEN")
        self.tg_chat = env("TELEGRAM_CHAT_ID")
        self.webhook = env("WEBHOOK_URL")

        self.dash_host = env("DASH_HOST", "0.0.0.0")
        self.dash_port = env_int("DASH_PORT", 8088)
        self.dash_user = env("DASH_USER", "admin")
        self.dash_pass = env("DASH_PASS")
        self.title = env("PANEL_TITLE", "Ramais")

        self.db_path = env("DB_PATH", os.path.join(BASE_DIR, "monitor.db"))
        self.history_days = env_int("HISTORY_DAYS", 90)
        self.tz = env("TIMEZONE", "America/Sao_Paulo")

    @property
    def has_api(self):
        return bool(self.mb_url and self.mb_key and self.mb_secret)

    def validate(self):
        errs = []
        if self.source not in ("ami", "api"):
            errs.append("STATUS_SOURCE deve ser 'ami' ou 'api'.")
        if self.source == "ami" and not (self.ami_user and self.ami_secret):
            errs.append("Preencha AMI_USER e AMI_SECRET (ou use STATUS_SOURCE=api).")
        if self.source == "api" and not self.has_api:
            errs.append("STATUS_SOURCE=api exige MB_URL, MB_API_KEY e MB_API_SECRET.")
        if self.sip_driver not in ("auto", "pjsip", "sip"):
            errs.append("SIP_DRIVER deve ser auto, pjsip ou sip.")
        loopback = self.dash_host in ("127.0.0.1", "localhost", "::1")
        if not self.dash_pass and not loopback:
            errs.append("Defina DASH_PASS: o painel está aberto na rede (DASH_HOST) e precisa de senha.")
        return errs


def matches(name, patterns):
    for p in patterns:
        if p.endswith("*") and name.startswith(p[:-1]):
            return True
        if name == p:
            return True
    return False


# --------------------------------------------------------------------------
# AMI (Asterisk Manager Interface)
# --------------------------------------------------------------------------
class AMIError(Exception):
    pass


class AMI:
    def __init__(self, host, port, user, secret, timeout=10):
        self.host, self.port, self.user, self.secret = host, port, user, secret
        self.timeout = timeout
        self.sock = None
        self.buf = b""
        self._aid = 0

    def __enter__(self):
        try:
            self.sock = socket.create_connection((self.host, self.port), self.timeout)
        except OSError as e:
            raise AMIError(f"não foi possível conectar em {self.host}:{self.port} ({e})")
        self.sock.settimeout(self.timeout)
        banner = self._readline()
        if b"Asterisk" not in banner:
            raise AMIError("a porta respondeu, mas não parece ser o AMI do Asterisk")
        aid = self._send({"Action": "Login", "Username": self.user,
                          "Secret": self.secret, "Events": "off"})
        while True:
            msg = self._read_message()
            if msg.get("ActionID") == aid and "Response" in msg:
                break
        if msg.get("Response") != "Success":
            raise AMIError("login recusado: " + msg.get("Message", "verifique usuário/senha e permit no manager.conf"))
        return self

    def __exit__(self, *exc):
        try:
            self._send({"Action": "Logoff"})
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass

    def _recv(self):
        try:
            chunk = self.sock.recv(65536)
        except socket.timeout:
            raise AMIError("tempo esgotado aguardando o AMI")
        if not chunk:
            raise AMIError("conexão AMI encerrada pelo servidor")
        self.buf += chunk

    def _readline(self):
        while b"\r\n" not in self.buf:
            self._recv()
        line, self.buf = self.buf.split(b"\r\n", 1)
        return line

    def _read_message(self):
        while b"\r\n\r\n" not in self.buf:
            self._recv()
        raw, self.buf = self.buf.split(b"\r\n\r\n", 1)
        msg = {}
        for line in raw.decode("utf-8", "replace").split("\r\n"):
            if ":" in line:
                k, v = line.split(":", 1)
                msg[k.strip()] = v.strip()
        return msg

    def _send(self, fields):
        self._aid += 1
        aid = f"mon{self._aid}"
        fields = dict(fields, ActionID=aid)
        data = "".join(f"{k}: {v}\r\n" for k, v in fields.items()) + "\r\n"
        self.sock.sendall(data.encode())
        return aid

    def list_action(self, action, complete_event):
        aid = self._send({"Action": action})
        items = []
        while True:
            msg = self._read_message()
            if msg.get("ActionID") != aid:
                continue
            if "Response" in msg:
                if msg["Response"] == "Error":
                    m = msg.get("Message", "")
                    if m.lower().startswith("no "):   # "No endpoints found", "No Contacts found"
                        return []
                    raise AMIError(f"{action}: {m}")
                continue
            if msg.get("Event") == complete_event:
                return items
            items.append(msg)


RE_URI_HOST = re.compile(r"@\[?([0-9A-Za-z.:-]+?)\]?(?::\d+)?(?:[;>]|$)")
RE_MS = re.compile(r"\((\d+)\s*ms\)", re.I)
RE_CHAN = re.compile(r"^(?:PJSIP|SIP)/(.+)-[0-9a-fA-F]+$")
IN_CALL_STATES = {"in use", "busy", "ringing", "ring+inuse", "on hold"}


def collect_pjsip(ami):
    endpoints = ami.list_action("PJSIPShowEndpoints", "EndpointListComplete")
    contacts = ami.list_action("PJSIPShowContacts", "ContactListComplete")
    out = {}
    for e in endpoints:
        name = e.get("ObjectName")
        if name:
            out[name] = {"online": False, "ip": "", "rtt_ms": None, "user_agent": "",
                         "in_call": e.get("DeviceState", "").lower() in IN_CALL_STATES}
    for c in contacts:
        ep = c.get("Endpoint") or c.get("EndpointName") or c.get("ObjectName", "").split(";@")[0]
        if ep not in out:
            continue
        status = c.get("Status", "").lower()
        if status in ("unreachable", "removed"):
            continue
        rec = out[ep]
        rec["online"] = True
        m = RE_URI_HOST.search(c.get("Uri", "") or c.get("URI", ""))
        rec["ip"] = c.get("ViaAddr") or (m.group(1) if m else rec["ip"])
        rec["user_agent"] = c.get("UserAgent", "") or rec["user_agent"]
        try:
            us = int(float(c.get("RoundtripUsec", "0") or 0))
            if us > 0:
                rec["rtt_ms"] = round(us / 1000)
        except ValueError:
            pass
    return out


def collect_sip(ami):
    peers = ami.list_action("SIPpeers", "PeerlistComplete")
    out = {}
    for p in peers:
        name = p.get("ObjectName")
        if not name:
            continue
        status = p.get("Status", "")
        ip = p.get("IPaddress", "")
        if ip in ("-none-", "(null)", "(Unspecified)"):
            ip = ""
        online = status.upper().startswith("OK") or (status.lower().startswith("unmonitored") and bool(ip))
        m = RE_MS.search(status)
        out[name] = {"online": online, "ip": ip, "rtt_ms": int(m.group(1)) if m else None,
                     "user_agent": "", "in_call": False}
    return out


def mark_calls(ami, snap):
    try:
        chans = ami.list_action("CoreShowChannels", "CoreShowChannelsComplete")
    except AMIError as e:
        log.debug("CoreShowChannels indisponível: %s", e)
        return
    for ch in chans:
        m = RE_CHAN.match(ch.get("Channel", ""))
        if m and m.group(1) in snap:
            snap[m.group(1)]["in_call"] = True


# --------------------------------------------------------------------------
# API MagnusBilling
# --------------------------------------------------------------------------
class MagnusAPI:
    """Cliente da API do MagnusBilling (mesma assinatura HMAC-SHA512 da classe PHP oficial)."""

    def __init__(self, url, key, secret, verify=True):
        self.url, self.key, self.secret, self.verify = url, key, secret, verify

    def _query(self, module, action, extra=None):
        req = dict(extra or {})
        req["module"] = module
        req["action"] = action
        t = time.time()
        req["nonce"] = f"{int(t)}{int((t % 1) * 1_000_000):06d}"
        post = urlencode(req)
        sign = hmac.new(self.secret.encode(), post.encode(), hashlib.sha512).hexdigest()
        r = requests.post(f"{self.url}/index.php/{module}/{action}", data=post, timeout=20,
                          verify=self.verify,
                          headers={"Key": self.key, "Sign": sign,
                                   "Content-Type": "application/x-www-form-urlencoded"})
        if r.status_code != 200:
            raise RuntimeError(f"API respondeu HTTP {r.status_code}: {r.text[:200]}")
        try:
            return r.json()
        except ValueError:
            raise RuntimeError(f"API não retornou JSON (confira MB_URL): {r.text[:200]}")

    def read_all(self, module, limit=500):
        rows, page = [], 1
        while True:
            data = self._query(module, "read", {"page": page, "start": (page - 1) * limit, "limit": limit})
            if isinstance(data, dict) and data.get("success") is False:
                raise RuntimeError("API recusou a leitura: " + str(data.get("msg") or data.get("errors") or data))
            batch = (data or {}).get("rows") or []
            rows += batch
            try:
                total = int(data.get("count") or data.get("total") or len(rows))
            except (TypeError, ValueError):
                total = len(rows)
            if not batch or len(rows) >= total or page > 200:
                return rows
            page += 1


def sip_row_meta(row):
    name = str(row.get("name") or row.get("defaultuser") or "").strip()
    client = row.get("idUserusername") or row.get("username") or row.get("accountcode") or ""
    return name, {"client": str(client), "callerid": str(row.get("callerid") or "")}


def status_from_linestatus(ls):
    s = str(ls or "").upper()
    if not s or any(w in s for w in ("UNREACH", "UNAVAIL", "UNKNOWN", "OFFLINE", "LAGGED")):
        return False, None
    m = RE_MS.search(s)
    online = any(w in s for w in ("OK", "REACH", "AVAIL", "USE", "ONLINE"))
    return online, int(m.group(1)) if m else None


# --------------------------------------------------------------------------
# Persistência
# --------------------------------------------------------------------------
class Store:
    def __init__(self, path):
        self.lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        with self.lock:
            self.db.executescript("""
                CREATE TABLE IF NOT EXISTS events(
                    id INTEGER PRIMARY KEY, ts REAL, ext TEXT,
                    from_status TEXT, to_status TEXT, duration REAL);
                CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
                CREATE INDEX IF NOT EXISTS idx_events_ext ON events(ext);
                CREATE TABLE IF NOT EXISTS state(
                    ext TEXT PRIMARY KEY, status TEXT, since REAL, alerted TEXT, last_seen REAL);
            """)
            self.db.commit()

    def add_event(self, ts, ext, frm, to, duration):
        with self.lock:
            self.db.execute("INSERT INTO events(ts,ext,from_status,to_status,duration) VALUES(?,?,?,?,?)",
                            (ts, ext, frm, to, duration))
            self.db.commit()

    def events(self, limit=100, ext=None):
        q = "SELECT ts,ext,from_status,to_status,duration FROM events"
        args = []
        if ext:
            q += " WHERE ext=?"
            args.append(ext)
        q += " ORDER BY ts DESC LIMIT ?"
        args.append(limit)
        with self.lock:
            rows = self.db.execute(q, args).fetchall()
        return [{"ts": r[0], "ext": r[1], "from": r[2], "to": r[3], "duration": r[4]} for r in rows]

    def load_state(self):
        with self.lock:
            rows = self.db.execute("SELECT ext,status,since,alerted,last_seen FROM state").fetchall()
        return {r[0]: {"status": r[1], "since": r[2], "alerted": r[3] or "", "last_seen": r[4]} for r in rows}

    def save_state(self, states):
        with self.lock:
            self.db.execute("DELETE FROM state")
            self.db.executemany("INSERT INTO state VALUES(?,?,?,?,?)",
                                [(s["ext"], s["status"], s["since"], s["alerted"], s.get("last_seen"))
                                 for s in states])
            self.db.commit()

    def prune(self, days):
        with self.lock:
            self.db.execute("DELETE FROM events WHERE ts < ?", (time.time() - days * 86400,))
            self.db.commit()


# --------------------------------------------------------------------------
# Alertas
# --------------------------------------------------------------------------
def fmt_dur(sec):
    sec = int(max(0, sec))
    if sec < 60:
        return f"{sec} s"
    m = sec // 60
    if m < 60:
        return f"{m} min"
    h, m = divmod(m, 60)
    if h < 24:
        return f"{h} h {m} min" if m else f"{h} h"
    d, h = divmod(h, 24)
    return f"{d} d {h} h" if h else f"{d} d"


def html_escape(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


class Notifier:
    def __init__(self, cfg):
        self.cfg = cfg

    @property
    def enabled(self):
        return bool((self.cfg.tg_token and self.cfg.tg_chat) or self.cfg.webhook)

    def send(self, text, payload):
        threading.Thread(target=self._deliver, args=(text, payload), daemon=True).start()

    def _deliver(self, text, payload):
        if self.cfg.tg_token and self.cfg.tg_chat:
            for chat in self.cfg.tg_chat.split(","):
                try:
                    r = requests.post(f"https://api.telegram.org/bot{self.cfg.tg_token}/sendMessage",
                                      json={"chat_id": chat.strip(), "text": text, "parse_mode": "HTML",
                                            "disable_web_page_preview": True}, timeout=15)
                    if r.status_code != 200:
                        log.warning("Telegram falhou (%s): %s", r.status_code, r.text[:200])
                except Exception as e:
                    log.warning("Telegram falhou: %s", e)
        if self.cfg.webhook:
            try:
                requests.post(self.cfg.webhook, json=payload, timeout=15)
            except Exception as e:
                log.warning("Webhook falhou: %s", e)

    @staticmethod
    def _label(s):
        extra = s.get("client") or s.get("callerid")
        return f"<b>{html_escape(s['ext'])}</b>" + (f" ({html_escape(extra)})" if extra else "")

    def down(self, items, now):
        if not items:
            return
        if len(items) == 1:
            s = items[0]
            text = (f"🔴 Ramal {self._label(s)} está OFFLINE\n"
                    f"Offline desde {time.strftime('%d/%m %H:%M', time.localtime(s['since']))} "
                    f"(há {fmt_dur(now - s['since'])})")
            if s.get("ip"):
                text += f"\nÚltimo IP: {html_escape(s['ip'])}"
        else:
            text = f"🔴 {len(items)} ramais ficaram OFFLINE\n"
            if len(items) >= self.cfg.mass_threshold:
                text += "⚠️ Muitos ao mesmo tempo: pode ser queda de link, firewall ou do servidor.\n"
            text += "\n".join("• " + self._label(s) for s in items[:40])
            if len(items) > 40:
                text += f"\n… e mais {len(items) - 40}"
        self.send(text, {"type": "down", "ts": now, "count": len(items),
                         "ramais": [self._public(s) for s in items]})

    def up(self, items, now):
        if not items:
            return
        if len(items) == 1:
            s, dur = items[0]
            text = f"🟢 Ramal {self._label(s)} voltou (ficou offline por {fmt_dur(dur)})"
        else:
            text = f"🟢 {len(items)} ramais voltaram\n" + "\n".join(
                f"• {self._label(s)}: offline por {fmt_dur(d)}" for s, d in items[:40])
        self.send(text, {"type": "up", "ts": now, "count": len(items),
                         "ramais": [dict(self._public(s), offline_seconds=round(d)) for s, d in items]})

    def monitor_error(self, err, now):
        self.send(f"⚠️ O monitor perdeu contato com o servidor de telefonia:\n{html_escape(err)}",
                  {"type": "monitor_error", "ts": now, "error": err})

    def monitor_ok(self, now):
        self.send("✅ O monitor voltou a falar com o servidor de telefonia.",
                  {"type": "monitor_ok", "ts": now})

    @staticmethod
    def _public(s):
        return {k: s.get(k) for k in ("ext", "client", "callerid", "ip", "since", "status")}


# --------------------------------------------------------------------------
# Monitor
# --------------------------------------------------------------------------
class Monitor:
    def __init__(self, cfg, store, notifier):
        self.cfg, self.store, self.notifier = cfg, store, notifier
        self.api = MagnusAPI(cfg.mb_url, cfg.mb_key, cfg.mb_secret, cfg.mb_verify_ssl) if cfg.has_api else None
        self.lock = threading.Lock()
        self.exts = {}
        self.persisted = store.load_state()
        self.meta, self.meta_at, self.meta_error = {}, 0, None
        self.error, self.error_alerted, self.error_since = None, False, None
        self.updated_at = None
        self.driver = cfg.sip_driver if cfg.sip_driver != "auto" else None
        self.first = True
        self.last_prune = 0

    # -- coleta ---------------------------------------------------------
    def refresh_meta(self, force=False):
        if not self.api or (not force and time.time() - self.meta_at < self.cfg.meta_refresh):
            return None
        try:
            rows = self.api.read_all("sip")
            meta = {}
            for row in rows:
                name, m = sip_row_meta(row)
                if name:
                    m["_line"] = row.get("lineStatus")
                    meta[name] = m
            self.meta, self.meta_at, self.meta_error = meta, time.time(), None
            return rows
        except Exception as e:
            self.meta_error = str(e)
            self.meta_at = time.time() - self.cfg.meta_refresh + 60   # tenta de novo em 1 min
            log.warning("API MagnusBilling: %s", e)
            if self.cfg.source == "api":
                raise
            return None

    def collect(self):
        if self.cfg.source == "api":
            self.refresh_meta(force=True)
            snap = {}
            for name, m in self.meta.items():
                online, rtt = status_from_linestatus(m.get("_line"))
                snap[name] = {"online": online, "ip": "", "rtt_ms": rtt, "user_agent": "", "in_call": False}
            return snap

        self.refresh_meta()
        with AMI(self.cfg.ami_host, self.cfg.ami_port, self.cfg.ami_user, self.cfg.ami_secret) as ami:
            if self.driver is None:
                try:
                    snap = collect_pjsip(ami)
                    self.driver = "pjsip"
                except AMIError as e:
                    log.info("PJSIP indisponível (%s); usando chan_sip", e)
                    snap = collect_sip(ami)
                    self.driver = "sip"
            elif self.driver == "pjsip":
                snap = collect_pjsip(ami)
            else:
                snap = collect_sip(ami)
            mark_calls(ami, snap)

        if self.meta and self.cfg.only_api_users:
            snap = {k: v for k, v in snap.items() if k in self.meta}
            for name in self.meta:   # cadastrado no Magnus mas não carregado no Asterisk
                snap.setdefault(name, {"online": False, "ip": "", "rtt_ms": None, "user_agent": "", "in_call": False})
        return snap

    # -- ciclo ----------------------------------------------------------
    def poll_once(self):
        now = time.time()
        try:
            snap = self.collect()
        except Exception as e:
            err = str(e)
            with self.lock:
                if self.error is None:
                    self.error_since = now
                self.error = err
            log.error("Falha na coleta: %s", err)
            if not self.error_alerted and now - self.error_since >= max(self.cfg.grace, 30):
                self.error_alerted = True
                self.notifier.monitor_error(err, now)
            return False

        if self.error_alerted:
            self.notifier.monitor_ok(now)
        with self.lock:
            self.error, self.error_alerted, self.error_since = None, False, None

        names = [n for n in snap
                 if (not self.cfg.watch_only or matches(n, self.cfg.watch_only))
                 and not matches(n, self.cfg.ignore)]
        went_down, came_up = [], []

        with self.lock:
            for ext in names:
                d = snap[ext]
                st = "online" if d["online"] else "offline"
                s = self.exts.get(ext)
                if s is None:
                    prev = self.persisted.get(ext)
                    if prev and prev["status"] == st:
                        s = {"ext": ext, "status": st, "since": prev["since"],
                             "alerted": prev["alerted"], "last_seen": prev.get("last_seen")}
                    else:
                        s = {"ext": ext, "status": st, "since": now, "last_seen": None,
                             # já offline na primeira leitura: não alerta (evita avalanche ao ligar o monitor)
                             "alerted": "silent" if (st == "offline" and self.first and not prev) else ""}
                        if prev and prev["status"] != st:
                            self.store.add_event(now, ext, prev["status"], st, now - (prev["since"] or now))
                            if st == "online" and prev["alerted"] == "sent":
                                came_up.append((s, now - prev["since"]))
                    self.exts[ext] = s
                elif s["status"] != st:
                    dur = now - s["since"]
                    self.store.add_event(now, ext, s["status"], st, dur)
                    if st == "online" and s["alerted"] == "sent":
                        came_up.append((s, dur))
                    s["status"], s["since"], s["alerted"] = st, now, ""

                m = self.meta.get(ext, {})
                s.update(client=m.get("client", ""), callerid=m.get("callerid", ""),
                         in_call=bool(d.get("in_call")) and st == "online",
                         rtt_ms=d.get("rtt_ms") if st == "online" else None,
                         user_agent=d.get("user_agent") or s.get("user_agent", ""))
                if st == "online":
                    s["last_seen"] = now
                    if d.get("ip"):
                        s["ip"] = d["ip"]
                elif d.get("ip"):
                    s["ip"] = d["ip"]

                if st == "offline" and not s["alerted"] and now - s["since"] >= self.cfg.grace:
                    s["alerted"] = "sent"
                    went_down.append(s)

            for ext in list(self.exts):
                if ext not in names:
                    del self.exts[ext]
            self.updated_at = now
            self.first = False
            states = list(self.exts.values())

        self.store.save_state(states)
        self.notifier.down(went_down, now)
        if self.cfg.alert_recovery:
            self.notifier.up(came_up, now)
        if now - self.last_prune > 86400:
            self.store.prune(self.cfg.history_days)
            self.last_prune = now
        return True

    def run_forever(self):
        while True:
            start = time.time()
            try:
                self.poll_once()
            except Exception:
                log.exception("Erro inesperado no ciclo")
            time.sleep(max(1, self.cfg.poll - (time.time() - start)))

    # -- dados para o painel ---------------------------------------------
    def snapshot(self):
        with self.lock:
            rows = []
            for s in self.exts.values():
                r = dict(s)
                r["alerted"] = s["alerted"] == "sent"
                rows.append(r)
            data = {
                "now": time.time(), "updated_at": self.updated_at, "error": self.error,
                "error_since": self.error_since, "api_error": self.meta_error,
                "source": self.cfg.source, "driver": self.driver, "poll": self.cfg.poll,
                "grace": self.cfg.grace, "title": self.cfg.title,
            }
        data["summary"] = {
            "total": len(rows),
            "online": sum(r["status"] == "online" for r in rows),
            "offline": sum(r["status"] == "offline" for r in rows),
            "in_call": sum(bool(r.get("in_call")) for r in rows),
        }
        data["ramais"] = rows
        return data


# --------------------------------------------------------------------------
# Servidor HTTP do painel
# --------------------------------------------------------------------------
def make_handler(monitor, store, cfg):
    index_path = os.path.join(BASE_DIR, "static", "index.html")

    class Handler(BaseHTTPRequestHandler):
        server_version = "MagnusMonitor"

        def log_message(self, *a):
            pass

        def _authorized(self):
            if not cfg.dash_pass:
                return True
            h = self.headers.get("Authorization", "")
            if not h.startswith("Basic "):
                return False
            try:
                u, p = base64.b64decode(h[6:]).decode("utf-8").split(":", 1)
            except Exception:
                return False
            return hmac.compare_digest(u, cfg.dash_user) and hmac.compare_digest(p, cfg.dash_pass)

        def _send(self, code, body, ctype):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj, code=200):
            self._send(code, json.dumps(obj, ensure_ascii=False).encode(), "application/json; charset=utf-8")

        def do_GET(self):
            url = urlparse(self.path)
            if url.path == "/health":
                return self._json({"ok": monitor.error is None, "updated_at": monitor.updated_at})
            if not self._authorized():
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="Painel de ramais"')
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if url.path in ("/", "/index.html"):
                with open(index_path, "rb") as f:
                    return self._send(200, f.read(), "text/html; charset=utf-8")
            if url.path == "/api/status":
                return self._json(monitor.snapshot())
            if url.path == "/api/events":
                q = parse_qs(url.query)
                try:
                    limit = min(500, max(1, int(q.get("limit", ["100"])[0])))
                except ValueError:
                    limit = 100
                return self._json(store.events(limit, q.get("ext", [None])[0]))
            self._json({"error": "não encontrado"}, 404)

    return Handler


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Painel de ramais online/offline com alertas")
    ap.add_argument("--env", default=os.path.join(BASE_DIR, ".env"), help="caminho do arquivo .env")
    ap.add_argument("--test", action="store_true", help="faz uma leitura, mostra o resultado e sai")
    ap.add_argument("--test-alert", action="store_true", help="envia um alerta de teste e sai")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    if not load_env(args.env):
        log.warning("Arquivo %s não encontrado; usando variáveis de ambiente.", args.env)
    cfg = Config()
    os.environ["TZ"] = cfg.tz
    if hasattr(time, "tzset"):
        time.tzset()

    errs = cfg.validate()
    if errs:
        for e in errs:
            log.error(e)
        sys.exit(2)

    notifier = Notifier(cfg)
    if args.test_alert:
        if not notifier.enabled:
            log.error("Nenhum canal configurado (TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID ou WEBHOOK_URL).")
            sys.exit(2)
        notifier._deliver("✅ Teste do monitor de ramais: os alertas estão chegando.",
                          {"type": "test", "ts": time.time()})
        log.info("Alerta de teste enviado.")
        return

    store = Store(cfg.db_path if not args.test else ":memory:")
    monitor = Monitor(cfg, store, notifier)

    if args.test:
        ok = monitor.poll_once()
        snap = monitor.snapshot()
        if not ok:
            log.error("Falhou: %s", snap["error"])
            sys.exit(1)
        if monitor.meta_error:
            log.warning("API MagnusBilling com erro (seguindo só com AMI): %s", monitor.meta_error)
        print(f"\nFonte: {snap['source']}  Driver: {snap['driver'] or '-'}  "
              f"Ramais da API: {len(monitor.meta)}")
        print(f"{'RAMAL':<18}{'STATUS':<10}{'IP':<18}{'RTT':<8}{'CLIENTE'}")
        for r in sorted(snap["ramais"], key=lambda r: (r["status"] != "offline", r["ext"])):
            rtt = f"{r['rtt_ms']} ms" if r.get("rtt_ms") is not None else "-"
            status = r["status"] + (" 📞" if r.get("in_call") else "")
            print(f"{r['ext']:<18}{status:<10}{r.get('ip') or '-':<18}{rtt:<8}{r.get('client') or ''}")
        s = snap["summary"]
        print(f"\nTotal {s['total']}  online {s['online']}  offline {s['offline']}  em ligação {s['in_call']}")
        return

    if not notifier.enabled:
        log.warning("Nenhum canal de alerta configurado: o painel funciona, mas ninguém será avisado.")
    threading.Thread(target=monitor.run_forever, daemon=True).start()
    server = ThreadingHTTPServer((cfg.dash_host, cfg.dash_port), make_handler(monitor, store, cfg))
    log.info("Painel em http://%s:%s  (fonte=%s, intervalo=%ss, carência=%ss)",
             cfg.dash_host, cfg.dash_port, cfg.source, cfg.poll, cfg.grace)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
