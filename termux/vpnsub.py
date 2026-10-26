#!/usr/bin/env python3
"""
vpnsub — бесплатные VPN-ключи под РФ: собирает их из открытых источников, проверяет с твоего
устройства и делает файлы-подписки. Работает в Termux (Android), Linux и macOS, нужен только Python 3.

  python vpnsub.py                 обновить подписки (на время проверки выключи VPN)
  python vpnsub.py --copy trusted  то же и скопировать подписку «максимальное доверие» в буфер (Termux:API)
  python vpnsub.py serve           локальная подписка http://127.0.0.1:8088/trusted.txt с автообновлением
  python vpnsub.py discover        найти новые репозитории с ключами на GitHub (--add — подключить их)
  python3 vpnsub.py router-setup   роутер с OpenWrt и Podkop: каждые 3 часа класть 15 лучших ключей в Podkop
  python3 vpnsub.py router-setup --sub 'ССЫЛКА'   то же, но основными будут ключи твоей платной подписки,
                                                 а бесплатные — резервом, если она не отвечает

Подписки:
  trusted.txt  максимальное доверие: только VLESS Reality напрямую к серверу, проверены из РФ или
               подтверждены 4+ независимыми источниками, сервер не в РФ/РБ/Китае/Иране/Казахстане
  safe.txt     минимальный риск: только шифрованные протоколы с проверкой сертификата, сервер не в России
  main.txt     основная подборка
  tor-bridges.txt  мосты для Tor Browser, проверенные из России

Нерабочие ключи остаются в подписке ещё 7 дней (в конце списка, с ⚠️): вдруг оживут.
Файлы лежат в ~/vpnsub/out, а если дан доступ к памяти (termux-setup-storage) — ещё и в Загрузки/vpnsub.
"""
import argparse
import base64
import binascii
import bisect
import collections
import concurrent.futures
import datetime
import hashlib
import http.server
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

VERSION = "1.0"
BASE_DIR = os.path.expanduser(os.environ.get("VPNSUB_DIR", "~/vpnsub"))
RAW_BASE = os.environ.get("VPNSUB_RAW_BASE", "https://raw.githubusercontent.com").rstrip("/")
API_BASE = os.environ.get("VPNSUB_API_BASE", "https://api.github.com").rstrip("/")
UA = f"Mozilla/5.0 (vpnsub/{VERSION})"

TESTED_IN_RU = {"igareck"}                       # проверяют сервера изнутри России
SURVEILLANCE = {"RU", "BY", "CN", "IR", "KZ"}    # страны с обязательной прослушкой трафика
MIN_OWNERS_WL, MIN_OWNERS_BL, MIN_OWNERS_TRUSTED = 3, 2, 4
QUOTA = {"ЧС": 450, "БС": 650}
MAX_PER_BACKEND = 3
PLACEHOLDER_IDS = {"00000000-0000-0000-0000-000000000000", "11111111-1111-1111-1111-111111111111"}

# (владелец/репозиторий, файл, метка): BL — обычный режим (ЧС), WL — белые списки (БС), MIX — смешанные
SOURCES = [
    ("igareck/vpn-configs-for-russia", "BLACK_VLESS_RUS.txt", "BL"),
    ("igareck/vpn-configs-for-russia", "BLACK_VLESS_RUS_mobile.txt", "BL"),
    ("igareck/vpn-configs-for-russia", "BLACK_SS+All_RUS.txt", "BL"),
    ("igareck/vpn-configs-for-russia", "BLACK_SS_WEAK_DPI_RUS.txt", "BL"),
    ("igareck/vpn-configs-for-russia", "Vless-Reality-White-Lists-Rus-Mobile.txt", "WL"),
    ("igareck/vpn-configs-for-russia", "WHITE-CIDR-RU-checked.txt", "WL"),
    ("igareck/vpn-configs-for-russia", "WHITE-SNI-RU-all.txt", "WL"),
    ("igareck/vpn-configs-for-russia", "WHITE-CIDR-RU-all.txt", "WL"),
    ("zieng2/wl", "vless_universal.txt", "WL"),
    ("zieng2/wl", "vless_lite.txt", "WL"),
    ("whoahaow/rjsxrd", "githubmirror/bypass/bypass-all.txt", "WL"),
    ("FLAT447/v2ray-lists", "WHITE_FULL.txt", "WL"),
    ("FLAT447/v2ray-lists", "BLACK_FULL.txt", "BL"),
    ("flaafix/AetrisVPN-white-list-lite", "AetrisVPN.txt", "WL"),
    ("flaafix/AetrisVPN", "AetrisVPN.txt", "MIX"),
    ("flaafix/AetrisVPN-black-list", "configs.txt", "BL"),
    ("wlunlocker/vpn-configs", "whitelist_all.txt", "WL"),
    ("wlunlocker/vpn-configs", "blacklist_all.txt", "BL"),
    ("Subzio/subzio", "WHITE_LIST_PROXY_COLLECTION.txt", "MIX"),
    ("solovyov-jenya2004/all_subs", "final_sorted", "MIX"),
    ("pie-with-jam/PulseProxy", "githubmirror/30.txt", "WL"),
    ("DarkRoyalty/shnajder-vpn-configs", "githubmirror/26.txt", "WL"),
    ("VOID-Anonymity/V.O.I.D-VPN_Bypass", "url_work.txt", "WL"),
    ("vladvarp/Prometheus", "WhiteList/vless.txt", "WL"),
    ("gooseteam-hackers/GooseVPN", "configs/balanced.txt", "WL"),
    ("gooseteam-hackers/GooseVPN", "configs/plus.txt", "WL"),
    ("Diversan313/apex-parser", "subs/main/alive_bs.txt", "WL"),
    ("Diversan313/apex-parser", "subs/main/alive_bl.txt", "BL"),
    ("RKPchannel/RKP_bypass_configs", "whitelist.txt", "WL"),
    ("RKPchannel/RKP_bypass_configs", "blacklist.txt", "BL"),
    ("terik21/HiddifySubs-VlessKeys", "WhiteKeys", "WL"),
    ("terik21/HiddifySubs-VlessKeys", "WhiteKeys2", "WL"),
    ("terik21/HiddifySubs-VlessKeys", "main", "BL"),
    ("terik21/HiddifySubs-VlessKeys", "SS", "BL"),
    ("terik21/HiddifySubs-VlessKeys", "Trojan", "BL"),
    ("Maskkost93/kizyak-vpn-4.0", "kizyakbeta6.txt", "WL"),
    ("Maskkost93/kizyak-vpn-4.0", "kizyakbeta6BL.txt", "BL"),
    ("Maskkost93/kizyak-vpn-4.0", "kizyakbeta7.txt", "BL"),
    ("Maskkost93/kizyak-vpn-4.0", "kizyakbeta8.txt", "BL"),
    ("Maskkost93/kizyak-vpn-4.0", "kizyaktestru.txt", "BL"),
    ("kort0881/vpn-vless-configs-russia", "data/githubmirror/ru-sni/vless.txt", "WL"),
    ("kort0881/vpn-vless-configs-russia", "data/githubmirror/ru-sni/trojan.txt", "WL"),
    ("kort0881/vpn-vless-configs-russia", "data/githubmirror/ru-sni/hysteria2.txt", "WL"),
    ("kort0881/vpn-vless-configs-russia", "data/githubmirror/ru-sni/hy2.txt", "WL"),
    ("kort0881/vpn-vless-configs-russia", "data/githubmirror/ru-sni-local/vless.txt", "WL"),
    ("kort0881/vpn-checker-backend", "checked/RU_Best/ru_white_all_WHITE.txt", "MIX"),
    ("kort0881/vpn-checker-backend", "checked/RU_Best/ru_white_all_BLACK.txt", "BL"),
    ("aviamastersgh/vpn-free-russia", "ru_configs.txt", "BL"),
    ("aviamastersgh/vpn-free-russia", "verified_configs.txt", "BL"),
    ("histeenn/VLESS-PO-GRIBI", "deploy/sub.txt", "BL"),
    ("svinakraft-maker/FlareFeed", "public/podpiska.txt", "BL"),
    ("luxxuria/harvester", "speed_tested.txt", "BL"),
    ("luxxuria/harvester", "ping_tested.txt", "BL"),
    ("luxxuria/harvester", "non_ru.txt", "BL"),
    ("tiagorrg/vless-checker", "docs/keys.json", "BL"),
]
WHITELIST_CIDR = [("pie-with-jam/PulseProxy", "source/config/cidrwhitelist.txt"),
                  ("whoahaow/rjsxrd", "source/config/cidrwhitelist.txt")]
WHITELIST_SNI = [("whoahaow/rjsxrd", "source/config/whitelist-all.txt"),
                 ("pie-with-jam/PulseProxy", "source/config/sni_domains.json")]
GEOIP_MMDB = [("P3TERX/GeoLite.mmdb@download", "GeoLite2-Country.mmdb"),
              ("gooseteam-hackers/GooseVPN", "configs/GeoLite2-Country.mmdb")]
TOR_BRIDGES = ("igareck/vpn-configs-for-russia", "TOR-BRIDGES/TOR_BRIDGES_TOP100.txt")
PODKOP_INIT = os.environ.get("VPNSUB_PODKOP_INIT", "/etc/init.d/podkop")
CRON_INIT = os.environ.get("VPNSUB_CRON_INIT", "/etc/init.d/cron")
CRONTAB = os.environ.get("VPNSUB_CRONTAB", "/etc/crontabs/root")


# ===================================== разбор ссылок ===========================================
LINE_START_RE = re.compile(r"^(vless|vmess|trojan|ss|hysteria2|hy2|tuic)://", re.I)
EMBED_RE = re.compile(r"(?:vless|vmess|trojan|ss|hysteria2|hy2|tuic)://[^\s\"'<>`\\]+", re.I)
B64_CHARS_RE = re.compile(r"^[A-Za-z0-9+/=_\-\s]+$")
COSMETIC_PARAMS = {"fp", "spx", "alpn", "allowinsecure", "insecure", "encryption", "headertype",
                   "packetencoding", "remarks", "remark", "name", "pinsha256", "pinnedpeercertsha256"}
FLAG_RE = re.compile("[\U0001F1E6-\U0001F1FF]{2}")


def b64decode_loose(s):
    s = s.strip().replace("\n", "").replace("\r", "").replace(" ", "").replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4), validate=False)


def maybe_decode_blob(text):
    if "://" in text[:4000]:
        return text
    compact = text.strip()
    if not compact or not B64_CHARS_RE.match(compact[:20000]):
        return text
    try:
        dec = b64decode_loose(compact).decode("utf-8", "replace")
    except (binascii.Error, ValueError):
        return text
    return dec if "://" in dec else text


def extract_links(text):
    out = []
    for raw in maybe_decode_blob(text).splitlines():
        line = raw.strip().strip("﻿")
        if not line or (line.startswith("#") and "://" not in line[:12]):
            continue
        if LINE_START_RE.match(line):
            out.append(line)
            continue
        if "://" not in line and len(line) > 40 and B64_CHARS_RE.match(line):
            try:
                dec = b64decode_loose(line).decode("utf-8", "replace")
                if "://" in dec:
                    out.extend(x.strip() for x in dec.splitlines() if LINE_START_RE.match(x.strip()))
                    continue
            except (binascii.Error, ValueError):
                pass
        out.extend(m.group(0) for m in EMBED_RE.finditer(line))
    return out


def extract_from_bytes(path, data):
    text = data.decode("utf-8", "replace")
    if path.endswith(".json"):
        try:
            links = []
            stack = [json.loads(text)]
            while stack:
                o = stack.pop()
                if isinstance(o, str):
                    if "://" in o:
                        links.extend(extract_links(o))
                elif isinstance(o, dict):
                    stack.extend(o.values())
                elif isinstance(o, list):
                    stack.extend(o)
            return links
        except ValueError:
            pass
    return extract_links(text)


BAD_HOSTS = {"localhost", "example.com", "127.0.0.1", "0.0.0.0", "1.1.1.1", "8.8.8.8", "google.com", "www.google.com"}


def host_ok(host):
    if not host:
        return False
    h = host.strip("[]").lower()
    if h in BAD_HOSTS:
        return False
    try:
        ip = ipaddress.ip_address(h)
        return not (ip.is_private or ip.is_loopback or ip.is_unspecified or ip.is_reserved
                    or ip.is_multicast or ip.is_link_local)
    except ValueError:
        pass
    return "." in h and len(h) <= 253 and re.fullmatch(r"[a-z0-9.\-_]+", h) is not None


def split_hostport(hp):
    hp = hp.strip()
    if hp.startswith("["):
        end = hp.find("]")
        if end == -1:
            return None, None
        rest = hp[end + 1:]
        return hp[:end + 1], (rest[1:] if rest.startswith(":") else "")
    if hp.count(":") == 1:
        return tuple(hp.split(":", 1))
    if ":" not in hp:
        return hp, ""
    host, port = hp.rsplit(":", 1)
    return "[" + host + "]", port


def port_ok(port, multi=False):
    if re.fullmatch(r"\d{1,5}", port or ""):
        return 1 <= int(port) <= 65535
    return bool(multi and re.fullmatch(r"\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*", port or ""))


def query_dict(q):
    return {k.lower(): v for k, v in urllib.parse.parse_qsl(q, keep_blank_values=False)}


def norm_query(q):
    d = {}
    for k, v in urllib.parse.parse_qsl(q, keep_blank_values=False):
        kl, v = k.lower(), v.strip()
        if kl in COSMETIC_PARAMS or not v:
            continue
        if kl in ("security", "type", "flow", "sni", "host", "peer", "obfs"):
            v = v.lower()
        if (kl, v) in (("type", "tcp"), ("security", "none")):
            continue
        d[kl] = v
    return tuple(sorted(d.items()))


class Parsed:
    __slots__ = ("scheme", "key", "host", "port", "remark", "link_body", "vmess_obj", "proto_label", "raw")


def parse_link(link):
    m = LINE_START_RE.match(link or "")
    if not m:
        return None
    scheme = m.group(1).lower()
    rest = link[m.end():]
    remark = ""
    if "#" in rest:
        rest, remark = rest.split("#", 1)
        remark = urllib.parse.unquote(remark).strip()
    p = Parsed()
    p.scheme, p.remark, p.vmess_obj, p.raw = ("hysteria2" if scheme == "hy2" else scheme), remark, None, link

    if scheme == "vmess" and "@" not in rest[:80]:
        try:
            obj = json.loads(b64decode_loose(rest.strip().split("?")[0]).decode("utf-8", "replace"))
        except (ValueError, binascii.Error, UnicodeDecodeError):
            return None
        if not isinstance(obj, dict):
            return None
        host, port = str(obj.get("add", "")).strip(), str(obj.get("port", "")).strip()
        uid = str(obj.get("id", "")).strip().lower()
        if not (host_ok(host) and port_ok(port) and uid):
            return None
        tls = str(obj.get("tls", "") or "").lower()
        p.key = ("vmess", uid, host.lower(), port, str(obj.get("net", "tcp") or "tcp").lower(), tls,
                 str(obj.get("host", "") or "").lower(), str(obj.get("path", "") or ""),
                 str(obj.get("sni", "") or "").lower(), str(obj.get("type", "none") or "none").lower())
        p.host, p.port, p.vmess_obj, p.link_body = host, port, obj, None
        p.remark = p.remark or str(obj.get("ps", "") or "")
        p.proto_label = "VMess" + (" TLS" if tls == "tls" else "")
        return p

    body, query = (rest.split("?", 1) + [""])[:2] if "?" in rest else (rest, "")
    body = body.rstrip("/")
    if scheme == "ss":
        method = password = None
        if "@" in body:
            userinfo, hp = body.rsplit("@", 1)
            ui = urllib.parse.unquote(userinfo)
            if ":" in ui:
                method, password = ui.split(":", 1)
            else:
                try:
                    dec = b64decode_loose(userinfo).decode("utf-8", "strict")
                except (ValueError, binascii.Error, UnicodeDecodeError):
                    return None
                if ":" in dec:
                    method, password = dec.split(":", 1)
        else:
            try:
                dec = b64decode_loose(body).decode("utf-8", "strict")
            except (ValueError, binascii.Error, UnicodeDecodeError):
                return None
            if "@" not in dec:
                return None
            ui, hp = dec.rsplit("@", 1)
            if ":" not in ui:
                return None
            method, password = ui.split(":", 1)
        if not method or not password:
            return None
        host, port = split_hostport(hp)
        if not (host_ok(host or "") and port_ok(port)):
            return None
        method = method.lower()
        if method in ("none", "plain", "table", "rc4", "rc4-md5", "aes-128-cfb", "aes-256-cfb", "chacha20",
                      "aes-192-cfb", "bf-cfb", "salsa20"):
            return None
        p.key = ("ss", method, password, host.lower(), port, norm_query(query))
        p.host, p.port, p.link_body = host, port, rest
        p.proto_label = "SS" + ("+plugin" if "plugin" in query_dict(query) else "")
        return p

    if "@" in body:
        userinfo, hp = body.rsplit("@", 1)
    elif p.scheme == "hysteria2":
        userinfo, hp = "", body
    else:
        return None
    hp = hp.split("/", 1)[0]
    userinfo = urllib.parse.unquote(userinfo).strip()
    host, port = split_hostport(hp)
    if not host_ok(host or ""):
        return None
    if not port_ok(port, multi=(p.scheme == "hysteria2")):
        if p.scheme == "hysteria2" and port == "":
            port = "443"
        else:
            return None
    if p.scheme in ("vless", "trojan", "tuic", "vmess") and not userinfo:
        return None
    qd = query_dict(query)
    if p.scheme == "vless":
        sec, typ = qd.get("security", "none").lower(), qd.get("type", "tcp").lower()
        if sec == "reality" and not qd.get("pbk"):
            return None
        label = "VLESS" + {"reality": " Reality", "tls": " TLS"}.get(sec, "")
        if typ not in ("tcp", "raw"):
            label += " " + {"ws": "WS", "grpc": "gRPC", "xhttp": "XHTTP", "splithttp": "XHTTP",
                            "httpupgrade": "HTTPUpgrade", "h2": "H2", "http": "H2", "kcp": "mKCP"}.get(typ, typ)
        p.proto_label = label
    elif p.scheme == "trojan":
        typ = qd.get("type", "tcp").lower()
        p.proto_label = "Trojan" + ("" if typ in ("tcp", "raw") else " " + {"ws": "WS", "grpc": "gRPC"}.get(typ, typ))
    else:
        p.proto_label = {"hysteria2": "Hysteria2", "tuic": "TUIC"}.get(p.scheme, "VMess")
    uid = userinfo.lower() if p.scheme in ("vless", "vmess") else userinfo
    p.key = (p.scheme, uid, host.lower(), port, norm_query(query))
    p.host, p.port, p.link_body = host, port, rest
    return p


def flag_from_remark(remark):
    m = FLAG_RE.search(remark or "")
    return m.group(0) if m else ""


def cc_to_flag(cc):
    cc = (cc or "").upper()
    return chr(0x1F1E6 + ord(cc[0]) - 65) + chr(0x1F1E6 + ord(cc[1]) - 65) if len(cc) == 2 and cc.isalpha() else ""


def flag_to_cc(flag):
    return "".join(chr(ord(c) - 0x1F1E6 + 65) for c in flag) if flag and len(flag) == 2 else ""


def render(p, name):
    if p.vmess_obj is not None:
        obj = dict(p.vmess_obj)
        obj["ps"] = name
        obj.setdefault("v", "2")
        raw = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return "vmess://" + base64.b64encode(raw).decode("ascii")
    body = re.sub(r"\s", lambda m: "%20" if m.group(0) == " " else "", p.link_body.strip())
    return f"{p.scheme}://{body}#{urllib.parse.quote(name, safe='')}"


def link_query(p):
    body = p.link_body or ""
    return query_dict(body.split("?", 1)[1]) if "?" in body else {}


# ===================================== GeoIP (MaxMind DB) =======================================
class MMDB:
    def __init__(self, buf):
        self.buf = buf
        idx = buf.rfind(b"\xab\xcd\xefMaxMind.com")
        if idx == -1:
            raise ValueError("not an mmdb file")
        start = idx + 14
        self.meta, _ = self._decode(start, start)
        self.nodes, self.rs = self.meta["node_count"], self.meta["record_size"]
        self.node_bytes = self.rs * 2 // 8
        self.tree_size = self.nodes * self.node_bytes
        self.data_base = self.tree_size + 16
        self._v4 = None

    def _decode(self, off, base=None):
        base = self.data_base if base is None else base
        b = self.buf
        ctrl = b[off]
        off += 1
        typ = ctrl >> 5
        if typ == 1:
            ss, v = (ctrl >> 3) & 3, ctrl & 7
            if ss == 0:
                ptr, off = (v << 8) | b[off], off + 1
            elif ss == 1:
                ptr, off = ((v << 16) | (b[off] << 8) | b[off + 1]) + 2048, off + 2
            elif ss == 2:
                ptr, off = ((v << 24) | (b[off] << 16) | (b[off + 1] << 8) | b[off + 2]) + 526336, off + 3
            else:
                ptr, off = struct.unpack(">I", b[off:off + 4])[0], off + 4
            return self._decode(base + ptr, base)[0], off
        if typ == 0:
            typ, off = 7 + b[off], off + 1
        size = ctrl & 0x1F
        if size == 29:
            size, off = 29 + b[off], off + 1
        elif size == 30:
            size, off = 285 + ((b[off] << 8) | b[off + 1]), off + 2
        elif size == 31:
            size, off = 65821 + ((b[off] << 16) | (b[off + 1] << 8) | b[off + 2]), off + 3
        if typ == 2:
            return b[off:off + size].decode("utf-8", "replace"), off + size
        if typ == 3:
            return struct.unpack(">d", b[off:off + 8])[0], off + 8
        if typ in (4,):
            return bytes(b[off:off + size]), off + size
        if typ in (5, 6, 8, 9, 10):
            return int.from_bytes(b[off:off + size], "big"), off + size
        if typ == 7:
            d = {}
            for _ in range(size):
                k, off = self._decode(off, base)
                d[k], off = self._decode(off, base)
            return d, off
        if typ == 11:
            arr = []
            for _ in range(size):
                v, off = self._decode(off, base)
                arr.append(v)
            return arr, off
        if typ == 14:
            return bool(size), off
        if typ == 15:
            return struct.unpack(">f", b[off:off + 4])[0], off + 4
        return None, off + size

    def _node(self, node, bit):
        off, b = node * self.node_bytes, self.buf
        if self.rs == 24:
            o = off + bit * 3
            return (b[o] << 16) | (b[o + 1] << 8) | b[o + 2]
        if self.rs == 28:
            if bit == 0:
                return ((b[off + 3] & 0xF0) << 20) | (b[off] << 16) | (b[off + 1] << 8) | b[off + 2]
            return ((b[off + 3] & 0x0F) << 24) | (b[off + 4] << 16) | (b[off + 5] << 8) | b[off + 6]
        o = off + bit * 4
        return struct.unpack(">I", b[o:o + 4])[0]

    def country(self, ip_str):
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return ""
        packed = ip.packed
        if ip.version == 4:
            if self._v4 is None:
                node = 0
                if self.meta.get("ip_version") == 6:
                    for _ in range(96):
                        if node >= self.nodes:
                            break
                        node = self._node(node, 0)
                self._v4 = node
            node, bits = self._v4, 32
        else:
            node, bits = 0, 128
        try:
            for i in range(bits):
                if node >= self.nodes:
                    break
                node = self._node(node, (packed[i >> 3] >> (7 - (i & 7))) & 1)
            if node <= self.nodes:
                return ""
            rec, _ = self._decode(self.tree_size + (node - self.nodes))
        except (IndexError, KeyError, struct.error):
            return ""
        c = (rec or {}).get("country") or (rec or {}).get("registered_country") or {}
        return c.get("iso_code", "") if isinstance(c, dict) else ""


# ===================================== загрузка =================================================
def http_get(url, timeout=40, headers=None):
    h = {"User-Agent": UA}
    h.update(headers or {})
    with urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=timeout) as r:
        return r.read()


def source_urls(repo, path):
    ref = "HEAD"
    if "@" in repo:
        repo, ref = repo.split("@", 1)
    qp = urllib.parse.quote(path, safe="/")
    urls = [f"{RAW_BASE}/{repo}/{ref}/{qp}"]
    if "raw.githubusercontent.com" in RAW_BASE:  # запасной путь, если raw.githubusercontent.com недоступен
        urls += [f"https://cdn.jsdelivr.net/gh/{repo}@{r}/{qp}" for r in ([ref] if ref != "HEAD" else ["main", "master"])]
    return urls


def cache_path(repo, path):
    return os.path.join(BASE_DIR, "cache", repo.replace("/", "__").replace("@", "__"), path)


def fetch(repo, path, max_age=0):
    """Скачивает файл (с ETag, чтобы не качать неизменившееся). При ошибке отдаёт сохранённую копию."""
    cp = cache_path(repo, path)
    have = os.path.exists(cp)
    if max_age and have and time.time() - os.path.getmtime(cp) < max_age:
        with open(cp, "rb") as f:
            return f.read(), "cache"
    etag = ""
    if have and os.path.exists(cp + ".etag"):
        with open(cp + ".etag", encoding="utf-8") as f:
            etag = f.read().strip()
    for i, url in enumerate(source_urls(repo, path)):
        try:
            hdr = {"If-None-Match": etag} if (etag and i == 0) else {}
            req = urllib.request.Request(url, headers={"User-Agent": UA, **hdr})
            with urllib.request.urlopen(req, timeout=40) as r:
                data = r.read()
                new_etag = r.headers.get("ETag", "") if i == 0 else ""
            if not data:
                continue
            os.makedirs(os.path.dirname(cp), exist_ok=True)
            with open(cp + ".tmp", "wb") as f:
                f.write(data)
            os.replace(cp + ".tmp", cp)
            if new_etag:
                with open(cp + ".etag", "w", encoding="utf-8") as f:
                    f.write(new_etag)
            elif os.path.exists(cp + ".etag"):
                os.remove(cp + ".etag")
            return data, "net"
        except urllib.error.HTTPError as e:
            if e.code == 304 and have:
                os.utime(cp)
                with open(cp, "rb") as f:
                    return f.read(), "net"
        except Exception:  # сеть, таймаут, обрыв — пробуем следующее зеркало
            pass
    if have:
        with open(cp, "rb") as f:
            return f.read(), "cache"
    return None, "fail"


def load_extra_sources():
    fp = os.path.join(BASE_DIR, "sources_extra.json")
    try:
        with open(fp, encoding="utf-8") as f:
            return [(r, p, "MIX") for r, p in json.load(f)]
    except (OSError, ValueError, TypeError):
        return []


# ===================================== сборка ===================================================
class Entry:
    __slots__ = ("kid", "p", "owners", "tags", "flag", "order", "stale", "status", "latency", "fail_since",
                 "geo", "wl")


def key_id(key):
    return hashlib.sha1(repr(key).encode("utf-8")).hexdigest()[:20]


def new_entry(kid, p, order):
    e = Entry()
    e.kid, e.p, e.owners, e.tags, e.flag, e.order = kid, p, set(), set(), "", order
    e.stale, e.status, e.latency, e.fail_since, e.geo, e.wl = False, None, None, None, "", False
    return e


def collect(downloaded):
    entries = {}
    for repo, path, tag, data in downloaded:
        if data is None:
            continue
        owner = repo.split("/")[0]
        for link in extract_from_bytes(path, data):
            p = parse_link(link)
            if not p or (p.scheme in ("vless", "vmess", "tuic") and p.key[1] in PLACEHOLDER_IDS):
                continue
            kid = key_id(p.key)
            e = entries.get(kid) or entries.setdefault(kid, new_entry(kid, p, len(entries)))
            e.owners.add(owner)
            e.tags.add(tag)
            if not e.flag:
                f = flag_from_remark(p.remark)
                if f and flag_to_cc(f) not in ("XX", "ZZ", "UN", "EU"):
                    e.flag = f
    return entries


class Whitelist:
    def __init__(self, cidr_blobs, sni_blobs):
        ranges = []
        for data in cidr_blobs:
            for line in data.decode("utf-8", "replace").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    net = ipaddress.ip_network(line, strict=False)
                except ValueError:
                    continue
                if net.version == 4:
                    ranges.append((int(net.network_address), int(net.broadcast_address)))
        ranges.sort()
        self.merged = []
        for a, b in ranges:
            if self.merged and a <= self.merged[-1][1] + 1:
                self.merged[-1][1] = max(self.merged[-1][1], b)
            else:
                self.merged.append([a, b])
        self.starts = [a for a, _ in self.merged]
        self.domains = set()
        for name, data in sni_blobs:
            text = data.decode("utf-8", "replace")
            if name.endswith(".json"):
                try:
                    self.domains.update(str(x).strip().lower() for x in json.loads(text))
                except ValueError:
                    pass
            else:
                self.domains.update(x.strip().lower() for x in text.splitlines() if x.strip() and not x.startswith("#"))

    def ip(self, host):
        try:
            ip = ipaddress.ip_address(host.strip("[]"))
        except ValueError:
            return False
        if ip.version != 4 or not self.starts:
            return False
        i = bisect.bisect_right(self.starts, int(ip)) - 1
        return i >= 0 and self.merged[i][0] <= int(ip) <= self.merged[i][1]

    def sni(self, sni):
        parts = (sni or "").split(".")
        return bool(sni) and any(".".join(parts[i:]) in self.domains for i in range(0, len(parts) - 1))


def sni_of(p):
    if p.vmess_obj is not None:
        return str(p.vmess_obj.get("sni") or p.vmess_obj.get("host") or "").lower()
    q = link_query(p)
    return (q.get("sni") or q.get("peer") or q.get("host") or "").lower()


def mode(e):
    return "БС" if ("WL" in e.tags or e.wl) else "ЧС"


def score(e):
    s = 10 * len(e.owners) + (100 if e.owners & TESTED_IN_RU else 0)
    lab = e.p.proto_label
    s += {"VLESS": 3, "Hysteria2": 2, "Trojan": 1.5, "TUIC": 1, "VMess": 0.5}.get(lab.split(" ")[0], 0)
    return s + (2 if "Reality" in lab else 0) + (1 if "XHTTP" in lab else 0)


def backend_key(p):
    if p.vmess_obj is not None:
        o = p.vmess_obj
        return ("vmess", str(o.get("id", "")).lower(), str(o.get("host", "")).lower(), str(o.get("path", "")),
                str(o.get("sni", "")).lower())
    q = link_query(p)
    cred = p.key[1] if p.scheme != "ss" else (p.key[1], p.key[2])
    return (p.scheme, cred, q.get("sni", q.get("peer", "")).lower(), q.get("host", "").lower(), q.get("path", ""),
            q.get("servicename", ""), q.get("pbk", ""), q.get("obfs-password", ""))


def truthy(v):
    return str(v).strip().lower() in ("1", "true", "yes")


def encrypted_and_verified(p):
    if p.vmess_obj is not None:
        o = p.vmess_obj
        return (str(o.get("tls", "")).lower() == "tls" and not truthy(o.get("allowInsecure", ""))
                and not truthy(o.get("skip-cert-verify", "")))
    q = link_query(p)
    if truthy(q.get("allowinsecure", "")) or truthy(q.get("insecure", "")):
        return False
    if p.scheme == "vless":
        return q.get("security", "none").lower() in ("reality", "tls")
    if p.scheme == "trojan":
        return q.get("security", "tls").lower() != "none"
    return p.scheme in ("hysteria2", "tuic")


def in_pool(e):
    """Кандидат в подписки: проверен из РФ или подтверждён несколькими независимыми источниками."""
    need = MIN_OWNERS_WL if mode(e) == "БС" else MIN_OWNERS_BL
    return bool(e.owners & TESTED_IN_RU) or len(e.owners) >= need


# ===================================== проверка с устройства ====================================
def tls_target(p):
    if p.vmess_obj is not None:
        o = p.vmess_obj
        if str(o.get("tls", "")).lower() == "tls":
            return str(o.get("sni") or o.get("host") or o.get("add") or ""), True
        return "", False
    q = link_query(p)
    if p.scheme == "vless" and q.get("security", "none").lower() in ("reality", "tls"):
        return q.get("sni") or q.get("host") or p.host.strip("[]"), True
    if p.scheme == "trojan" and q.get("security", "tls").lower() != "none":
        return q.get("sni") or q.get("peer") or q.get("host") or p.host.strip("[]"), True
    return "", False


def check_one(e, timeout):
    """TCP-соединение и, для TLS/Reality, TLS-рукопожатие с нужным SNI. None — проверить нельзя (UDP)."""
    p = e.p
    if p.scheme in ("hysteria2", "tuic") or not str(p.port).isdigit():
        return None, None, None
    sni, use_tls = tls_target(p)
    t0 = time.monotonic()
    try:
        with socket.create_connection((p.host.strip("[]"), int(p.port)), timeout=timeout) as s:
            peer = s.getpeername()[0]
            if use_tls:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s.settimeout(timeout)
                try:
                    ipaddress.ip_address(sni)
                    sni = None
                except ValueError:
                    pass
                with ctx.wrap_socket(s, server_hostname=sni or None):
                    pass
        return True, int((time.monotonic() - t0) * 1000), peer
    except Exception:
        return False, None, None


def run_checks(entries, workers, timeout, geo=None):
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(check_one, e, timeout): e for e in entries}
        done = 0
        for fut in concurrent.futures.as_completed(futs):
            e = futs[fut]
            e.status, e.latency, peer = fut.result()
            if peer and not e.geo and geo is not None:
                e.geo = geo.country(peer)
            done += 1
            if done % 200 == 0 or done == len(futs):
                print(f"\r  проверено {done}/{len(futs)}", end="", flush=True)
    print()


def my_country():
    for url in ("https://api.country.is/", "https://ipinfo.io/json"):
        try:
            return json.loads(http_get(url, timeout=8)).get("country", "") or ""
        except Exception:
            continue
    return ""


# ===================================== состояние и вывод =========================================
def load_json(fp, default):
    try:
        with open(fp, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def save_json(fp, obj):
    os.makedirs(os.path.dirname(fp), exist_ok=True)
    with open(fp + ".tmp", "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, separators=(",", ":"))
    os.replace(fp + ".tmp", fp)


def b64(s):
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


def write_sub(out_dir, fname, title, lst, stamp, checked):
    links = []
    for i, e in enumerate(lst, 1):
        warn = "⚠️ " if e.status is False or (e.status is None and e.fail_since) else ""
        links.append(render(e.p, f"{warn}{e.flag} {e.p.proto_label} · {mode(e)} · {i:04d}"))
    alive = sum(1 for e in lst if not (e.status is False or (e.status is None and e.fail_since)))
    header = ["#profile-title: base64:" + b64(title), "#profile-update-interval: 3",
              "#announce: base64:" + b64(f"Обновлено {stamp} · {len(links)} серверов"
                                         + (f" · с твоего устройства отвечают {alive}" if checked else ""))]
    with open(os.path.join(out_dir, fname), "w", encoding="utf-8") as f:
        f.write("\n".join(header + links) + "\n")
    return len(links), len(links) - alive


def select(entries, now, grace):
    """Основная, «минимальный риск» и «максимальное доверие»; живые раньше, нерабочие (в пределах 7 дней) в конце."""
    alive_first = lambda e: (e.status is False or (e.status is None and e.fail_since is not None))  # noqa: E731
    usable = [e for e in entries.values() if in_pool(e)
              and not (e.fail_since is not None and now - e.fail_since > grace)]
    by_score = sorted(usable, key=lambda e: (alive_first(e), -score(e), e.order))
    main, per_backend, taken = [], collections.Counter(), collections.Counter()
    for e in by_score:
        if e.owners & TESTED_IN_RU:
            main.append(e)
            per_backend[backend_key(e.p)] += 1
    for e in by_score:
        if e.owners & TESTED_IN_RU:
            continue
        m, bk = mode(e), backend_key(e.p)
        if taken[m] >= QUOTA[m] or per_backend[bk] >= MAX_PER_BACKEND:
            continue
        per_backend[bk] += 1
        taken[m] += 1
        main.append(e)
    safe = [e for e in main if encrypted_and_verified(e.p) and e.flag not in ("🇷🇺", "🌐") and e.geo != "RU"]
    trusted, seen = [], set()
    for e in sorted(safe, key=lambda e: (alive_first(e), -score(e), e.order)):
        if e.p.scheme != "vless" or link_query(e.p).get("security", "").lower() != "reality":
            continue
        if not (e.owners & TESTED_IN_RU or len(e.owners) >= MIN_OWNERS_TRUSTED):
            continue
        if flag_to_cc(e.flag) in SURVEILLANCE or e.geo in SURVEILLANCE:
            continue
        bk = backend_key(e.p)
        if bk not in seen:
            seen.add(bk)
            trusted.append(e)
    order = lambda e: (alive_first(e), mode(e) == "БС", -score(e), e.latency if e.latency is not None else 99999, e.order)  # noqa: E731
    return sorted(main, key=order), sorted(safe, key=order), sorted(trusted, key=order)


def update(args, quiet=False):
    t_start = time.time()
    now = time.time()
    grace = args.grace * 86400
    out_dir = os.path.join(BASE_DIR, "out")
    os.makedirs(out_dir, exist_ok=True)
    sources = SOURCES + load_extra_sources()
    print(f"Скачиваю {len(sources)} источников…")
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(lambda s: fetch(s[0], s[1]), sources))
    downloaded = [(r, p, t, data) for (r, p, t), (data, _) in zip(sources, results)]
    net_ok = sum(1 for _, how in results if how == "net")
    from_cache = sum(1 for _, how in results if how == "cache")
    failed = [f"{r}/{p}" for (r, p, _), (_, how) in zip(sources, results) if how == "fail"]
    print(f"  из сети: {net_ok}, из сохранённых копий: {from_cache}, недоступно: {len(failed)}")
    if net_ok + from_cache == 0:
        sys.exit("Не удалось скачать ни одного источника. Проверь интернет (GitHub должен открываться).")

    aux = {}
    for repo, path in WHITELIST_CIDR + WHITELIST_SNI:
        aux[(repo, path)] = fetch(repo, path, max_age=86400)[0]
    wl = Whitelist([aux[k] for k in WHITELIST_CIDR if aux.get(k)],
                   [(k[1], aux[k]) for k in WHITELIST_SNI if aux.get(k)])
    geo = None
    for repo, path in GEOIP_MMDB:
        data, _ = fetch(repo, path, max_age=7 * 86400)
        if data and len(data) > 100_000:
            try:
                geo = MMDB(data)
                break
            except (ValueError, KeyError, IndexError):
                continue
    tor, _ = fetch(*TOR_BRIDGES)

    entries = collect(downloaded)
    n_unique = len(entries)

    # --- состояние: что видели раньше, что перестало работать
    state_fp = os.path.join(BASE_DIR, "state.json")
    state = load_json(state_fp, {"items": {}})
    items = state.get("items", {})
    had_state = bool(items)
    fresh_keys = set(entries)
    restored = 0
    for kid, st in list(items.items()):
        if kid in entries:
            continue
        if now - st.get("last_seen", 0) > grace:
            del items[kid]
            continue
        p = parse_link(st.get("link", ""))
        if not p:
            del items[kid]
            continue
        e = new_entry(kid, p, len(entries))
        e.owners, e.tags, e.flag, e.stale = set(st.get("owners", [])), set(st.get("tags", [])), st.get("flag", ""), True
        entries[kid] = e
        restored += 1

    for e in entries.values():
        e.wl = "WL" not in e.tags and (wl.ip(e.p.host) or wl.sni(sni_of(e.p)))
        host = e.p.host.strip("[]")
        if geo is not None:
            try:
                ipaddress.ip_address(host)
                e.geo = geo.country(host)
            except ValueError:
                pass
        if not e.flag:
            e.flag = cc_to_flag(e.geo) or "🌐"
        st = items.get(e.kid, {})
        e.fail_since = st.get("fail_since")

    pool = [e for e in entries.values() if in_pool(e)]
    new_keys = [e.kid for e in pool if e.kid in fresh_keys and e.kid not in items]

    # --- проверка доступности с этого устройства
    checked = ok = 0
    did_check = False
    if args.no_check:
        print("Проверку пропускаю (--no-check).")
    else:
        country = "" if args.force_check else my_country()
        if country and country != "RU" and not args.force_check:
            print(f"⚠️  Похоже, сейчас включён VPN (твой IP из {country}). Проверка из-за него была бы неточной — "
                  "пропускаю. Выключи VPN (или добавь Termux в исключения) и запусти снова.")
        else:
            resolvable = sorted((e for e in pool if not e.p.host.startswith("[")),
                                key=lambda e: (-score(e), e.order))[:args.check_limit]
            print(f"Проверяю {len(resolvable)} серверов с этого устройства (1–3 минуты)…")
            run_checks(resolvable, args.workers, args.timeout, geo)
            for e in resolvable:
                if e.status is True:
                    e.fail_since = None
                elif e.status is False:
                    e.fail_since = e.fail_since or now
            checked = sum(1 for e in resolvable if e.status is not None)
            ok = sum(1 for e in resolvable if e.status is True)
            did_check = True
            if checked and ok == 0:
                did_check = False
                print("⚠️  Ни один сервер не ответил — похоже, нет интернета. Результат проверки не сохраняю.")
                for e in resolvable:
                    e.status, e.fail_since = None, items.get(e.kid, {}).get("fail_since")
                checked = 0

    # --- сохранить состояние (только то, что может попасть в подписки)
    for e in pool:
        st = items.setdefault(e.kid, {"first_seen": now})
        if not e.stale:
            st.update(link=e.p.raw, owners=sorted(e.owners), tags=sorted(e.tags), flag=e.flag, last_seen=now)
        st["fail_since"] = e.fail_since
        if e.status is True:
            st["last_ok"] = now
    for kid in [k for k, st in items.items() if st.get("fail_since") and now - st["fail_since"] > grace]:
        items.pop(kid, None)
    state["items"], state["updated"] = items, now
    save_json(state_fp, state)

    # --- подписки
    main, safe, trusted = select(entries, now, grace)
    stamp = datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=3))).strftime("%d.%m.%Y %H:%M МСК")
    res = {
        "trusted.txt": write_sub(out_dir, "trusted.txt", "VPN · максимальное доверие", trusted, stamp, checked > 0),
        "safe.txt": write_sub(out_dir, "safe.txt", "VPN · минимальный риск", safe, stamp, checked > 0),
        "main.txt": write_sub(out_dir, "main.txt", "VPN · основная", main, stamp, checked > 0),
    }
    n_bridges = 0
    if tor:
        bridges = [x.strip() for x in tor.decode("utf-8", "replace").splitlines()
                   if x.strip() and not x.lstrip().startswith("#")]
        n_bridges = len(bridges)
        with open(os.path.join(out_dir, "tor-bridges.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(bridges) + "\n")

    shared = os.path.expanduser("~/storage/downloads")
    copied_to = ""
    if os.path.isdir(shared):
        dst = os.path.join(shared, "vpnsub")
        os.makedirs(dst, exist_ok=True)
        for fn in list(res) + (["tor-bridges.txt"] if n_bridges else []):
            shutil.copyfile(os.path.join(out_dir, fn), os.path.join(dst, fn))
        copied_to = "Загрузки/vpnsub"

    print(f"\nУникальных ключей: {n_unique}" + (f", новых с прошлого раза: {len(new_keys)}" if had_state else "")
          + (f", пропали из источников, но держим до 7 дней: {restored}" if restored else ""))
    if checked:
        print(f"С этого устройства доступны {ok} из {checked}")
    print("Подписки:")
    names = {"trusted.txt": "максимальное доверие", "safe.txt": "минимальный риск", "main.txt": "основная"}
    for fn, (n, bad) in res.items():
        print(f"  {fn:<12} {names[fn]}: {n}" + (f" (⚠️ нерабочих: {bad})" if bad else ""))
    if n_bridges:
        print(f"  tor-bridges.txt мосты для Tor Browser: {n_bridges}")
    print(f"Папка: {out_dir}" + (f"  и  {copied_to}" if copied_to else ""))
    print(f"Готово за {int(time.time() - t_start)} с.")

    if getattr(args, "copy", None):
        copy_to_clipboard(os.path.join(out_dir, f"{args.copy}.txt"))
    if getattr(args, "podkop", 0):
        own = None
        if getattr(args, "sub", None):
            own = fetch_own_subs(args.sub, args.sub_ua)
            if not own:
                print("Не удалось получить ключи своей подписки — Podkop не трогаю.")
                return out_dir
            if did_check:
                run_checks([e for e in own if not e.p.host.startswith("[")], args.workers, args.timeout, geo)
        apply_podkop(trusted, args.podkop, args.podkop_section, own=own, fallback_n=getattr(args, "fallback", 10))
    return out_dir


# ===================================== роутер: Podkop ===========================================
UNSAFE_BODY_RE = re.compile(r"['\"`$\\]")


def podkop_compatible(p, own=False):
    """Что Podkop точно запустит. Бесплатные ключи — только VLESS Reality поверх TCP или gRPC.
    Своя (платная) подписка — ещё VLESS/Trojan с TLS или WebSocket, Shadowsocks и Hysteria2.
    XHTTP не берём: со старым движком Podkop из-за такого ключа не запустится."""
    if p.vmess_obj is not None or UNSAFE_BODY_RE.search(p.link_body or ""):
        return False
    q = link_query(p)
    typ = q.get("type", "tcp").lower()
    if not own:
        return (p.scheme == "vless" and q.get("security", "").lower() == "reality" and bool(q.get("pbk"))
                and typ in ("tcp", "raw", "grpc"))
    if p.scheme in ("vless", "trojan"):
        sec = q.get("security", "none" if p.scheme == "vless" else "tls").lower()
        return (typ in ("tcp", "raw", "grpc", "ws") and sec in ("reality", "tls", "none")
                and (sec != "reality" or bool(q.get("pbk"))))
    if p.scheme == "ss":
        return "plugin" not in q
    return p.scheme == "hysteria2"


def uci(*args, check=True):
    r = subprocess.run(["uci", *args], capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"uci {' '.join(args[:2])}: {r.stderr.strip() or r.returncode}")
    return r.stdout.strip()


def device_id():
    """Постоянный идентификатор устройства для подписок с лимитом устройств (заголовок x-hwid)."""
    fp = os.path.join(BASE_DIR, "hwid")
    try:
        with open(fp, encoding="utf-8") as f:
            hw = f.read().strip()
        if hw:
            return hw
    except OSError:
        pass
    seed = ""
    for path in ("/etc/machine-id", "/sys/class/net/br-lan/address", "/sys/class/net/eth0/address"):
        try:
            with open(path, encoding="utf-8") as f:
                seed = f.read().strip()
            if seed:
                break
        except OSError:
            continue
    hw = hashlib.sha256((seed or os.urandom(16).hex()).encode()).hexdigest()[:16]
    os.makedirs(BASE_DIR, exist_ok=True)
    with open(fp, "w", encoding="utf-8") as f:
        f.write(hw)
    return hw


def fetch_own_subs(urls, ua):
    """Скачивает свою подписку (например, платную) и достаёт из неё ключи."""
    found = {}
    for url in urls:
        host = urllib.parse.urlsplit(url).netloc or "подписка"
        headers = {"User-Agent": ua, "Accept": "*/*", "x-hwid": device_id(), "x-device-os": "Linux",
                   "x-device-model": "OpenWrt router", "x-ver-os": os.uname().release if hasattr(os, "uname") else ""}
        try:
            data = http_get(url, timeout=30, headers=headers)
        except urllib.error.HTTPError as e:
            print(f"Своя подписка {host}: сервер ответил ошибкой {e.code}. Проверь ссылку и что подписка оплачена.")
            continue
        except Exception as e:
            print(f"Своя подписка {host}: не удалось скачать ({e.__class__.__name__}).")
            continue
        text = data.decode("utf-8", "replace")
        if text.lstrip()[:15].lower().startswith(("<!doctype", "<html")):
            print(f"Своя подписка {host}: вместо ключей пришла веб-страница. Попробуй другой клиент: --sub-ua Happ/3.7.0")
            continue
        n = 0
        for link in extract_links(text):
            p = parse_link(link)
            if not p:
                continue
            kid = key_id(p.key)
            if kid not in found:
                e = new_entry(kid, p, len(found))
                e.owners, e.flag = {"own"}, flag_from_remark(p.remark) or "🌐"
                found[kid] = e
                n += 1
        print(f"Своя подписка {host}: {keys_word(n)}")
    return list(found.values())


def keys_word(n):
    n = abs(n)
    if n % 10 == 1 and n % 100 != 11:
        return f"{n} ключ"
    if 2 <= n % 10 <= 4 and not 12 <= n % 100 <= 14:
        return f"{n} ключа"
    return f"{n} ключей"


def _alive(e):
    return e.status is not False and not (e.status is None and e.fail_since)


def _stable_pick(current, candidates, n, keep_names):
    """Оставляет уже стоящие живые ключи на своих местах и добирает лучшими новыми до N."""
    by_key = {e.p.key: e for e in candidates}
    keep, keys = [], set()
    for link in current:
        p = parse_link(link)
        if p and p.key in by_key and p.key not in keys and len(keep) < n:
            keep.append(link)
            keys.add(p.key)
    kept = len(keep)
    for e in candidates:
        if len(keep) >= n:
            break
        if e.p.key not in keys:
            name = (e.p.remark if keep_names and e.p.remark else f"{e.flag} {e.p.proto_label}")
            keep.append(render(e.p, name))
            keys.add(e.p.key)
    return keep, kept


def apply_podkop(trusted, n, section="main", own=None, fallback_n=10):
    """Кладёт ключи в URLTest Podkop: свою подписку (если есть) основной группой, бесплатные — резервом.
    Рабочие ключи, что уже стоят, не трогает, поэтому Podkop перезапускается только при изменениях."""
    if not shutil.which("uci") or not os.path.exists(PODKOP_INIT):
        print("Podkop не найден. Установи его и запусти снова.")
        return False
    opt = f"podkop.{section}"
    if subprocess.run(["uci", "-q", "get", opt], capture_output=True).returncode != 0:
        print(f"В настройках Podkop нет секции «{section}». Укажи свою: --podkop-section ИМЯ")
        return False
    conn = uci("-q", "get", f"{opt}.connection_type", check=False)
    if conn and conn != "proxy":
        print(f"Podkop работает в режиме «{conn}», а нужен «proxy». Переключи «Тип подключения» на «Прокси» в "
              "LuCI → Службы → Podkop и запусти снова.")
        return False
    current = uci("-q", "get", f"{opt}.urltest_proxy_links", check=False).split()
    current_fb = uci("-q", "get", f"{opt}.urltest_fallback_links", check=False).split()
    cur_type = uci("-q", "get", f"{opt}.proxy_config_type", check=False)
    free = [e for e in trusted if podkop_compatible(e.p) and _alive(e)]
    if own is not None:
        mine = [e for e in own if podkop_compatible(e.p, own=True)]
        if not mine:
            print("Podkop: в своей подписке нет ключей, которые он умеет запускать. Оставляю как было.")
            return False
        mine_alive = [e for e in mine if e.status is not False] or mine  # если не ответил никто — всё равно ставим
        main, kept = _stable_pick(current, mine_alive, n, keep_names=True)
        main_keys = {parse_link(x).key for x in main}
        fb_cands = [e for e in free if e.p.key not in main_keys]
        fallback, _ = _stable_pick(current_fb, fb_cands, fallback_n, keep_names=False) if fallback_n > 0 else ([], 0)
    else:
        main, kept = _stable_pick(current, free, n, keep_names=False)
        fallback = []
    if not main:
        print("Podkop: подходящих живых ключей нет, оставляю как было.")
        return False
    if main == current and fallback == current_fb and cur_type == "urltest":
        print(f"Podkop: все ключи на месте и живы ({len(main)}" + (f" + резерв {len(fallback)}" if fallback else "")
              + "), ничего не меняю.")
        return True
    uci("-q", "delete", f"{opt}.urltest_proxy_links", check=False)
    for link in main:
        uci("add_list", f"{opt}.urltest_proxy_links={link}")
    uci("-q", "delete", f"{opt}.urltest_fallback_links", check=False)
    for link in fallback:
        uci("add_list", f"{opt}.urltest_fallback_links={link}")
    uci("set", f"{opt}.proxy_config_type=urltest")
    uci("commit", "podkop")
    r = subprocess.run([PODKOP_INIT, "restart"], capture_output=True, text=True)
    what = "своей подписки" if own is not None else "бесплатных"
    print(f"Podkop: {keys_word(len(main))} {what} в режиме URLTest (прежних осталось {kept}, новых {len(main) - kept})"
          + (f", в резерве {keys_word(len(fallback))} из бесплатных" if fallback else "")
          + ("" if r.returncode == 0 else f", но перезапуск не удался: {r.stderr.strip()[:200]}"))
    return r.returncode == 0


ROUTER_CFG = os.path.join(BASE_DIR, "router.json")


def router_setup(args):
    if not os.path.exists(PODKOP_INIT) or not shutil.which("uci"):
        sys.exit("Сначала установи Podkop (см. инструкцию), потом запусти router-setup снова.")
    cfg = {"podkop": getattr(args, "podkop", 0) or 15, "section": getattr(args, "podkop_section", "main"),
           "subs": getattr(args, "sub", None) or [], "sub_ua": getattr(args, "sub_ua", "v2rayN/7.15"),
           "fallback": getattr(args, "fallback", 10)}
    save_json(ROUTER_CFG, cfg)
    os.chmod(ROUTER_CFG, 0o600)  # там может быть личная ссылка на подписку
    script = os.path.abspath(sys.argv[0] if sys.argv and sys.argv[0].endswith(".py") else __file__)
    line = f"23 */3 * * * {sys.executable or '/usr/bin/python3'} {script} router-update >/tmp/vpnsub.log 2>&1"
    try:
        with open(CRONTAB, encoding="utf-8") as f:
            lines = [x.rstrip("\n") for x in f if "vpnsub.py" not in x]
    except OSError:
        lines = []
    os.makedirs(os.path.dirname(CRONTAB), exist_ok=True)
    with open(CRONTAB, "w", encoding="utf-8") as f:
        f.write("\n".join([x for x in lines if x.strip()] + [line]) + "\n")
    for action in ("enable", "restart"):
        subprocess.run([CRON_INIT, action], capture_output=True)
    print("Автообновление включено: каждые 3 часа, лог — /tmp/vpnsub.log"
          + (" (своя подписка подключена)" if cfg["subs"] else "") + "\n")
    router_update(args)


def router_update(args):
    cfg = load_json(ROUTER_CFG, None)
    if not cfg:
        sys.exit("Роутер ещё не настроен: запусти python3 vpnsub.py router-setup")
    args.podkop, args.podkop_section = cfg.get("podkop", 15), cfg.get("section", "main")
    args.sub, args.fallback = cfg.get("subs") or None, cfg.get("fallback", 10)
    args.sub_ua = cfg.get("sub_ua") or getattr(args, "sub_ua", "v2rayN/7.15")
    update(args)


def copy_to_clipboard(fp):
    tool = shutil.which("termux-clipboard-set")
    if not tool:
        print("Для копирования в буфер установи приложение Termux:API и выполни: pkg install termux-api")
        return
    with open(fp, encoding="utf-8") as f:
        subprocess.run([tool], input=f.read(), text=True, check=False)
    print(f"📋 {os.path.basename(fp)} скопирован в буфер: в VPN-приложении нажми «+» → «Импорт из буфера».")


# ===================================== локальная подписка ========================================
def serve(args):
    out_dir = os.path.join(BASE_DIR, "out")
    os.makedirs(out_dir, exist_ok=True)

    def loop():
        while True:
            try:
                update(args)
            except SystemExit as e:
                print("Обновление не удалось:", e)
            except Exception as e:  # сервер не должен падать из-за одного неудачного обновления
                print("Ошибка обновления:", repr(e))
            time.sleep(max(1, args.interval) * 3600)

    threading.Thread(target=loop, daemon=True).start()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            name = os.path.basename(urllib.parse.urlsplit(self.path).path.strip("/")) or ""
            files = sorted(f for f in os.listdir(out_dir) if f.endswith(".txt"))
            code = 200
            if not name:
                body = ("vpnsub: подписки\n\n" + "\n".join(f"http://127.0.0.1:{args.port}/{f}" for f in files)).encode()
            elif name in files:
                with open(os.path.join(out_dir, name), "rb") as f:
                    body = f.read()
            else:
                code, body = 404, "Нет такого файла (возможно, подписка ещё собирается)\n".encode()
            self.send_response(code)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"\nЛокальная подписка запущена. Добавь в VPN-приложение как подписку по ссылке:\n"
          f"  http://127.0.0.1:{args.port}/trusted.txt   (или safe.txt, main.txt)\n"
          f"Обновление каждые {args.interval} ч. Не закрывай Termux (лучше выполнить termux-wake-lock). Стоп: Ctrl+C\n")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("Остановлено.")


# ===================================== поиск новых источников ====================================
DISCOVER_QUERIES = ["topic:free-vpn-russia", "topic:vpn-russia", "topic:whitelist-bypass",
                    "vless russia configs", "белые списки vless", "vless reality россия"]
NAME_HINT = re.compile(r"(vless|vmess|trojan|hy2|hysteria|sub|config|key|white|black|bypass|mix|all|ru|lte|mobile|proxy|list|wl|bl)", re.I)


def gh_api(path):
    headers = {"Accept": "application/vnd.github+json"}
    if os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = "Bearer " + os.environ["GITHUB_TOKEN"]
    return json.loads(http_get(API_BASE + path, timeout=30, headers=headers))


def discover(args):
    since = (datetime.date.today() - datetime.timedelta(days=7)).isoformat()
    known = {r.split("@")[0].lower() for r, _, _ in SOURCES + load_extra_sources()}
    found = {}
    print("Ищу на GitHub репозитории с ключами, обновлённые за неделю…")
    for i, q in enumerate(DISCOVER_QUERIES):
        try:
            data = gh_api(f"/search/repositories?q={urllib.parse.quote(q)}+pushed:>={since}&sort=updated&per_page=30")
        except Exception as e:
            print(f"  поиск «{q}» не удался: {e}")
            continue
        for r in data.get("items", []):
            found[r["full_name"]] = r
        if i < len(DISCOVER_QUERIES) - 1:
            time.sleep(args.pause)  # без токена GitHub разрешает 10 поисков в минуту
    cands = [r for r in found.values() if r["full_name"].lower() not in known and not r.get("fork")
             and not r.get("archived") and r.get("stargazers_count", 0) >= args.min_stars]
    cands.sort(key=lambda r: -r.get("stargazers_count", 0))
    print(f"  кандидатов: {len(cands)} (из {len(found)} найденных, уже подключённые и без звёзд отброшены)")
    results = []
    for r in cands[:args.limit]:
        try:
            tree = gh_api(f"/repos/{r['full_name']}/git/trees/{urllib.parse.quote(r.get('default_branch') or 'HEAD')}?recursive=1")
        except Exception as e:
            print(f"  {r['full_name']}: не удалось получить список файлов ({e})")
            continue
        files = []
        for t in tree.get("tree", []):
            path = t.get("path", "")
            base = path.rsplit("/", 1)[-1].lower()
            ext = os.path.splitext(base)[1]
            if (t.get("type") != "blob" or not (200 < t.get("size", 0) < 4_000_000) or ext not in ("", ".txt", ".sub")
                    or base.startswith(("readme", "license", "requirements", "changelog", "package"))
                    or any(seg.startswith(".") for seg in path.split("/"))):
                continue
            files.append((len(NAME_HINT.findall(path)), path))
        files.sort(reverse=True)
        for _, path in files[:6]:
            try:
                data = http_get(f"{RAW_BASE}/{r['full_name']}/HEAD/{urllib.parse.quote(path, safe='/')}", timeout=30)
            except Exception:
                continue
            n = sum(1 for link in extract_from_bytes(path, data) if parse_link(link))
            if n >= 20:
                results.append((r["full_name"], path, n, r.get("stargazers_count", 0), (r.get("pushed_at") or "")[:10]))
    if not results:
        print("Новых источников не нашлось.")
        return
    print("\nНовые источники:")
    for repo, path, n, stars, pushed in results:
        print(f"  ★{stars:<5} {repo}/{path} — ключей: {n}, обновлён {pushed}")
    if args.add:
        fp = os.path.join(BASE_DIR, "sources_extra.json")
        cur = load_json(fp, [])
        have = {(a, b) for a, b in cur}
        cur += [[repo, path] for repo, path, *_ in results if (repo, path) not in have]
        save_json(fp, cur)
        print(f"\nПодключено. Они попадут в подписки при следующем обновлении (список: {fp}).")
    else:
        print("\nЧтобы подключить их, запусти: python vpnsub.py discover --add")


# ===================================== запуск ===================================================
def main():
    ap = argparse.ArgumentParser(description="Бесплатные VPN-ключи под РФ: сбор, проверка с устройства, подписки.",
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("command", nargs="?", default="update", choices=["update", "serve", "discover", "router-setup", "router-update"])
    ap.add_argument("--copy", choices=["trusted", "safe", "main"], help="скопировать подписку в буфер (Termux:API)")
    ap.add_argument("--no-check", action="store_true", help="не проверять доступность серверов")
    ap.add_argument("--force-check", action="store_true", help="проверять, даже если похоже, что включён VPN")
    ap.add_argument("--grace", type=float, default=7, help="сколько дней держать нерабочие ключи (по умолчанию 7)")
    ap.add_argument("--workers", type=int, default=128, help="параллельных проверок (по умолчанию 128)")
    ap.add_argument("--timeout", type=float, default=4, help="таймаут проверки, секунд (по умолчанию 4)")
    ap.add_argument("--check-limit", type=int, default=3000, help="сколько лучших серверов проверять (по умолчанию 3000)")
    ap.add_argument("--host", default="127.0.0.1", help="serve: адрес (по умолчанию 127.0.0.1)")
    ap.add_argument("--port", type=int, default=8088, help="serve: порт (по умолчанию 8088)")
    ap.add_argument("--interval", type=int, default=3, help="serve: обновлять каждые N часов (по умолчанию 3)")
    ap.add_argument("--podkop", type=int, default=0, metavar="N",
                    help="роутер: положить N лучших живых ключей в Podkop (URLTest)")
    ap.add_argument("--podkop-section", default="main", help="роутер: секция Podkop (по умолчанию main)")
    ap.add_argument("--sub", action="append", metavar="URL",
                    help="роутер: своя (например, платная) подписка — её ключи станут основными, бесплатные пойдут в резерв")
    ap.add_argument("--sub-ua", default="v2rayN/7.15", help="роутер: каким клиентом представляться своей подписке")
    ap.add_argument("--fallback", type=int, default=10, help="роутер: сколько бесплатных ключей держать в резерве (0 — нисколько)")
    ap.add_argument("--add", action="store_true", help="discover: сразу подключить найденные источники")
    ap.add_argument("--min-stars", type=int, default=5, help="discover: минимум звёзд у репозитория")
    ap.add_argument("--limit", type=int, default=20, help="discover: сколько репозиториев проверять")
    ap.add_argument("--pause", type=float, default=7, help=argparse.SUPPRESS)
    args = ap.parse_args()
    if args.command == "serve":
        serve(args)
    elif args.command == "discover":
        discover(args)
    elif args.command == "router-setup":
        router_setup(args)
    elif args.command == "router-update":
        router_update(args)
    else:
        update(args)


if __name__ == "__main__":
    main()
