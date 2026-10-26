"""Parsing / normalisation helpers for proxy share links (vless, vmess, trojan, ss, hysteria2, tuic)."""
import base64
import binascii
import ipaddress
import json
import re
import urllib.parse

SCHEMES = ("vless", "vmess", "trojan", "ss", "hysteria2", "hy2", "tuic")
LINE_START_RE = re.compile(r"^(vless|vmess|trojan|ss|hysteria2|hy2|tuic)://", re.I)
EMBED_RE = re.compile(r"(?:vless|vmess|trojan|ss|hysteria2|hy2|tuic)://[^\s\"'<>`\\]+", re.I)
B64_CHARS_RE = re.compile(r"^[A-Za-z0-9+/=_\-\s]+$")

# query params that do not change which server/route you land on
COSMETIC_PARAMS = {"fp", "spx", "alpn", "allowinsecure", "insecure", "encryption", "headertype",
                   "packetencoding", "remarks", "remark", "name", "pinsha256", "pinnedpeercertsha256"}


def b64decode_loose(s: str) -> bytes:
    s = s.strip().replace("\n", "").replace("\r", "").replace(" ", "")
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s, validate=False)


def maybe_decode_blob(text: str) -> str:
    """If a whole file is a base64 subscription, decode it."""
    head = text[:4000]
    if "://" in head:
        return text
    compact = text.strip()
    if not compact or not B64_CHARS_RE.match(compact[:20000]):
        return text
    try:
        dec = b64decode_loose(compact).decode("utf-8", "replace")
    except (binascii.Error, ValueError):
        return text
    return dec if "://" in dec else text


def extract_links(text: str):
    text = maybe_decode_blob(text)
    out = []
    for raw in text.splitlines():
        line = raw.strip().strip("﻿")
        if not line or line.startswith("#") and "://" not in line[:12]:
            continue
        if LINE_START_RE.match(line):
            out.append(line)
            continue
        # a line that is itself base64 of a link list (rare)
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


def walk_json_strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from walk_json_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from walk_json_strings(v)


def extract_from_file(path: str):
    with open(path, "rb") as f:
        data = f.read()
    text = data.decode("utf-8", "replace")
    if path.endswith(".json"):
        try:
            obj = json.loads(text)
            links = []
            for s in walk_json_strings(obj):
                if "://" in s:
                    links.extend(extract_links(s))
            return links
        except ValueError:
            pass
    return extract_links(text)


BAD_HOSTS = {"localhost", "example.com", "127.0.0.1", "0.0.0.0", "1.1.1.1", "8.8.8.8", "google.com",
             "www.google.com"}


def host_ok(host: str) -> bool:
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
    if "." not in h or len(h) > 253:
        return False
    return re.fullmatch(r"[a-z0-9.\-_]+", h) is not None


def split_hostport(hp: str):
    hp = hp.strip()
    if hp.startswith("["):
        end = hp.find("]")
        if end == -1:
            return None, None
        host = hp[: end + 1]
        rest = hp[end + 1:]
        port = rest[1:] if rest.startswith(":") else ""
        return host, port
    if hp.count(":") == 1:
        host, port = hp.split(":", 1)
        return host, port
    if ":" not in hp:
        return hp, ""
    # unbracketed ipv6 with port
    host, port = hp.rsplit(":", 1)
    return "[" + host + "]", port


PORT_RE = re.compile(r"^\d{1,5}$")
MULTIPORT_RE = re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$")


def port_ok(port: str, multi=False) -> bool:
    if PORT_RE.match(port or ""):
        return 1 <= int(port) <= 65535
    if multi and MULTIPORT_RE.match(port or ""):
        return True
    return False


def norm_query(q: str):
    pairs = urllib.parse.parse_qsl(q, keep_blank_values=False)
    d = {}
    for k, v in pairs:
        kl = k.lower()
        if kl in COSMETIC_PARAMS:
            continue
        v = v.strip()
        if not v:
            continue
        if kl in ("security", "type", "flow", "sni", "host", "peer", "obfs"):
            v = v.lower()
        if kl == "type" and v == "tcp":
            continue
        if kl == "security" and v == "none":
            continue
        d[kl] = v
    return tuple(sorted(d.items()))


def query_dict(q: str):
    return {k.lower(): v for k, v in urllib.parse.parse_qsl(q, keep_blank_values=False)}


class Parsed:
    __slots__ = ("scheme", "key", "host", "port", "remark", "link_body", "vmess_obj", "proto_label")


def parse_link(link: str):
    """Return Parsed or None if invalid."""
    m = LINE_START_RE.match(link)
    if not m:
        return None
    scheme = m.group(1).lower()
    rest = link[m.end():]
    remark = ""
    if scheme != "vmess" or "#" in rest:
        if "#" in rest:
            rest, remark = rest.split("#", 1)
            remark = urllib.parse.unquote(remark).strip()
    p = Parsed()
    p.scheme = "hysteria2" if scheme == "hy2" else scheme
    p.remark = remark
    p.vmess_obj = None

    if scheme == "vmess":
        body = rest.strip()
        obj = None
        if "@" not in body[:80]:
            try:
                obj = json.loads(b64decode_loose(body.split("?")[0]).decode("utf-8", "replace"))
            except (ValueError, binascii.Error, UnicodeDecodeError):
                obj = None
        if isinstance(obj, dict):
            host = str(obj.get("add", "")).strip()
            port = str(obj.get("port", "")).strip()
            uid = str(obj.get("id", "")).strip().lower()
            if not (host_ok(host) and port_ok(port) and uid):
                return None
            net = str(obj.get("net", "tcp") or "tcp").lower()
            tls = str(obj.get("tls", "") or "").lower()
            key = ("vmess", uid, host.lower(), port, net, tls,
                   str(obj.get("host", "") or "").lower(), str(obj.get("path", "") or ""),
                   str(obj.get("sni", "") or "").lower(), str(obj.get("type", "none") or "none").lower())
            p.key, p.host, p.port = key, host, port
            p.vmess_obj = obj
            p.remark = p.remark or str(obj.get("ps", "") or "")
            p.link_body = None
            p.proto_label = "VMess" + (" TLS" if tls == "tls" else "")
            return p
        # vmess in uri form vmess://uuid@host:port?...
        scheme_body = body
    else:
        scheme_body = rest

    if scheme == "ss":
        body = scheme_body
        query = ""
        if "?" in body:
            body, query = body.split("?", 1)
        body = body.rstrip("/")
        method = password = None
        if "@" in body:
            userinfo, hp = body.rsplit("@", 1)
            ui = urllib.parse.unquote(userinfo)
            if ":" in ui:
                method, password = ui.split(":", 1)
            else:
                try:
                    dec = b64decode_loose(userinfo).decode("utf-8", "strict")
                    if ":" in dec:
                        method, password = dec.split(":", 1)
                except (ValueError, binascii.Error, UnicodeDecodeError):
                    return None
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
            return None  # insecure / stream ciphers — useless and detectable
        p.key = ("ss", method, password, host.lower(), port, norm_query(query))
        p.host, p.port = host, port
        p.link_body = rest
        qd = query_dict(query)
        p.proto_label = "SS" + ("+plugin" if "plugin" in qd else "")
        return p

    # generic userinfo@host:port?query  (vless, trojan, hysteria2, tuic, vmess-uri)
    body = scheme_body
    query = ""
    if "?" in body:
        body, query = body.split("?", 1)
    body = body.rstrip("/")
    if "@" not in body:
        if p.scheme == "hysteria2":
            userinfo, hp = "", body
        else:
            return None
    else:
        userinfo, hp = body.rsplit("@", 1)
    if "/" in hp:
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
        sec = qd.get("security", "none").lower()
        if sec == "reality" and not qd.get("pbk"):
            return None
        typ = qd.get("type", "tcp").lower()
        label = "VLESS"
        if sec == "reality":
            label += " Reality"
        elif sec == "tls":
            label += " TLS"
        if typ not in ("tcp", "raw"):
            label += " " + {"ws": "WS", "grpc": "gRPC", "xhttp": "XHTTP", "splithttp": "XHTTP",
                            "httpupgrade": "HTTPUpgrade", "h2": "H2", "http": "H2", "kcp": "mKCP"}.get(typ, typ)
        p.proto_label = label
    elif p.scheme == "trojan":
        typ = qd.get("type", "tcp").lower()
        p.proto_label = "Trojan" + ("" if typ in ("tcp", "raw") else " " + {"ws": "WS", "grpc": "gRPC"}.get(typ, typ))
    elif p.scheme == "hysteria2":
        p.proto_label = "Hysteria2"
    elif p.scheme == "tuic":
        p.proto_label = "TUIC"
    else:
        p.proto_label = "VMess"
    uid = userinfo.lower() if p.scheme in ("vless", "vmess") else userinfo
    p.key = (p.scheme, uid, host.lower(), port, norm_query(query))
    p.host, p.port = host, port
    p.link_body = rest
    return p


FLAG_RE = re.compile("[\U0001F1E6-\U0001F1FF]{2}")


def flag_from_remark(remark: str):
    m = FLAG_RE.search(remark or "")
    return m.group(0) if m else ""


def cc_to_flag(cc: str) -> str:
    cc = (cc or "").upper()
    if len(cc) != 2 or not cc.isalpha():
        return ""
    return chr(0x1F1E6 + ord(cc[0]) - 65) + chr(0x1F1E6 + ord(cc[1]) - 65)


def flag_to_cc(flag: str) -> str:
    if not flag or len(flag) != 2:
        return ""
    return "".join(chr(ord(c) - 0x1F1E6 + 65) for c in flag)


def render(p: Parsed, new_remark: str) -> str:
    if p.vmess_obj is not None:
        obj = dict(p.vmess_obj)
        obj["ps"] = new_remark
        if "v" not in obj:
            obj["v"] = "2"
        raw = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return "vmess://" + base64.b64encode(raw).decode("ascii")
    scheme = p.scheme
    body = re.sub(r"\s", lambda m: "%20" if m.group(0) == " " else "", p.link_body.strip())
    return f"{scheme}://{body}#{urllib.parse.quote(new_remark, safe='')}"
