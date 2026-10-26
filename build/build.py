"""Собирает подписку из скачанных источников: python3 build/build.py _src out"""
import base64
import bisect
import collections
import datetime
import ipaddress
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from parse_lib import (extract_from_file, parse_link, flag_from_remark, flag_to_cc,  # noqa: E402
                       cc_to_flag, render, query_dict)
from sources import SOURCES, TESTED_IN_RU, WHITELIST_CIDR, WHITELIST_SNI  # noqa: E402
from mmdb import Reader  # noqa: E402

SRC = sys.argv[1] if len(sys.argv) > 1 else "_src"
OUT = sys.argv[2] if len(sys.argv) > 2 else "out"
MIN_OWNERS_WL = int(os.environ.get("MIN_OWNERS_WL", "3"))   # сколько независимых источников должны подтвердить БС-сервер
MIN_OWNERS_BL = int(os.environ.get("MIN_OWNERS_BL", "2"))   # ...и ЧС-сервер, чтобы попасть в основную подписку
QUOTA = {"ЧС": int(os.environ.get("QUOTA_BL", "450")), "БС": int(os.environ.get("QUOTA_WL", "650"))}
MAX_PER_BACKEND = int(os.environ.get("MAX_PER_BACKEND", "3"))  # не больше N вариантов одного и того же сервера
REPO = os.environ.get("GITHUB_REPOSITORY", "")
PLACEHOLDER_IDS = {"00000000-0000-0000-0000-000000000000", "11111111-1111-1111-1111-111111111111"}
os.makedirs(OUT, exist_ok=True)


def local_path(repo, path):
    return os.path.join(SRC, repo.split("@", 1)[0].replace("/", "__"), path)


class Entry:
    __slots__ = ("p", "owners", "tags", "flag", "order")


# ---- 1. собрать и убрать дубли ------------------------------------------------------
entries = {}
for repo, path, tag in SOURCES:
    fp = local_path(repo, path)
    if not os.path.exists(fp):
        print(f"skip (not downloaded): {repo}/{path}")
        continue
    owner = repo.split("/")[0]
    for link in extract_from_file(fp):
        p = parse_link(link)
        if not p or (p.scheme in ("vless", "vmess", "tuic") and p.key[1] in PLACEHOLDER_IDS):
            continue
        e = entries.get(p.key)
        if e is None:
            e = Entry()
            e.p, e.owners, e.tags, e.flag, e.order = p, set(), set(), "", len(entries)
            entries[p.key] = e
        e.owners.add(owner)
        e.tags.add(tag)
        if not e.flag:
            f = flag_from_remark(p.remark)
            if f and flag_to_cc(f) not in ("XX", "ZZ", "UN", "EU"):
                e.flag = f

# ---- 2. метка БС: IP сервера в белых диапазонах операторов или SNI из белого списка доменов
ranges = []
for repo, path in WHITELIST_CIDR:
    fp = local_path(repo, path)
    if not os.path.exists(fp):
        continue
    for line in open(fp, encoding="utf-8", errors="replace"):
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
merged = []
for a, b in ranges:
    if merged and a <= merged[-1][1] + 1:
        merged[-1][1] = max(merged[-1][1], b)
    else:
        merged.append([a, b])
starts = [a for a, _ in merged]

wl_domains = set()
for repo, path in WHITELIST_SNI:
    fp = local_path(repo, path)
    if not os.path.exists(fp):
        continue
    if fp.endswith(".json"):
        try:
            wl_domains.update(str(x).strip().lower() for x in json.load(open(fp, encoding="utf-8")))
        except ValueError:
            pass
    else:
        wl_domains.update(x.strip().lower() for x in open(fp, encoding="utf-8", errors="replace")
                          if x.strip() and not x.startswith("#"))


def ip_whitelisted(host):
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    if ip.version != 4 or not starts:
        return False
    v = int(ip)
    i = bisect.bisect_right(starts, v) - 1
    return i >= 0 and merged[i][0] <= v <= merged[i][1]


def sni_of(p):
    if p.vmess_obj is not None:
        return str(p.vmess_obj.get("sni") or p.vmess_obj.get("host") or "").lower()
    body = p.link_body or ""
    q = query_dict(body.split("?", 1)[1]) if "?" in body else {}
    return (q.get("sni") or q.get("peer") or q.get("host") or "").lower()


def sni_whitelisted(sni):
    if not sni:
        return False
    parts = sni.split(".")
    return any(".".join(parts[i:]) in wl_domains for i in range(0, len(parts) - 1))


for e in entries.values():
    if "WL" not in e.tags and (ip_whitelisted(e.p.host) or sni_whitelisted(sni_of(e.p))):
        e.tags.add("WL")

# ---- 3. флаг страны: из названия у источника, иначе по IP через GeoLite2 ---------------
geo = None
gp = os.path.join(SRC, "geoip.path")
if os.path.exists(gp):
    try:
        geo = Reader(os.path.join(SRC, open(gp).read().strip()))
    except (OSError, ValueError) as err:
        print("GeoIP unavailable:", err)
for e in entries.values():
    if not e.flag and geo is not None:
        try:
            ipaddress.ip_address(e.p.host.strip("[]"))
            cc = geo.country(e.p.host.strip("[]"))
            if cc:
                e.flag = cc_to_flag(cc)
        except ValueError:
            pass
    if not e.flag:
        e.flag = "🌐"

# ---- 4. ранжирование и отбор основной подписки -----------------------------------------
PROTO_BONUS = {"VLESS": 3, "Hysteria2": 2, "Trojan": 1.5, "TUIC": 1, "VMess": 0.5, "SS": 0}


def score(e):
    s = 10 * len(e.owners) + (100 if e.owners & TESTED_IN_RU else 0)
    lab = e.p.proto_label
    s += PROTO_BONUS.get(lab.split(" ")[0], 0) + (2 if "Reality" in lab else 0) + (1 if "XHTTP" in lab else 0)
    return s


def backend_key(p):
    if p.vmess_obj is not None:
        o = p.vmess_obj
        return ("vmess", str(o.get("id", "")).lower(), str(o.get("host", "")).lower(), str(o.get("path", "")),
                str(o.get("sni", "")).lower())
    body = p.link_body or ""
    q = query_dict(body.split("?", 1)[1]) if "?" in body else {}
    cred = p.key[1] if p.scheme != "ss" else (p.key[1], p.key[2])
    return (p.scheme, cred, q.get("sni", q.get("peer", "")).lower(), q.get("host", "").lower(), q.get("path", ""),
            q.get("servicename", ""), q.get("pbk", ""), q.get("obfs-password", ""))


def mode(e):
    return "БС" if "WL" in e.tags else "ЧС"


by_score = sorted(entries.values(), key=lambda e: (-score(e), e.order))
main, per_backend, taken = [], collections.Counter(), collections.Counter()
for e in by_score:  # всё, что проверено изнутри России
    if e.owners & TESTED_IN_RU:
        main.append(e)
        per_backend[backend_key(e.p)] += 1
for e in by_score:  # плюс подтверждённые несколькими независимыми источниками
    if e.owners & TESTED_IN_RU:
        continue
    m = mode(e)
    if len(e.owners) < (MIN_OWNERS_WL if m == "БС" else MIN_OWNERS_BL) or taken[m] >= QUOTA[m]:
        continue
    bk = backend_key(e.p)
    if per_backend[bk] >= MAX_PER_BACKEND:
        continue
    per_backend[bk] += 1
    taken[m] += 1
    main.append(e)

order_key = lambda e: (mode(e) == "БС", -score(e), e.order)  # noqa: E731  сначала ЧС, потом БС
main.sort(key=order_key)
full = sorted(entries.values(), key=order_key)

if len(main) < 100:
    sys.exit(f"основная подписка подозрительно мала ({len(main)}) — публикацию пропускаем")


# ---- 4б. «минимальный риск» для личного пользования -----------------------------------------
# из основной подписки: только шифрованный канал до сервера с проверкой сертификата (Reality/TLS/QUIC),
# сервер не в России и страна известна
def truthy(v):
    return str(v).strip().lower() in ("1", "true", "yes")


def encrypted_and_verified(p):
    if p.vmess_obj is not None:
        o = p.vmess_obj
        return (str(o.get("tls", "")).lower() == "tls" and not truthy(o.get("allowInsecure", ""))
                and not truthy(o.get("skip-cert-verify", "")))
    body = p.link_body or ""
    q = query_dict(body.split("?", 1)[1]) if "?" in body else {}
    if truthy(q.get("allowinsecure", "")) or truthy(q.get("insecure", "")):
        return False
    if p.scheme == "vless":
        return q.get("security", "none").lower() in ("reality", "tls")
    if p.scheme == "trojan":
        return q.get("security", "tls").lower() != "none"
    return p.scheme in ("hysteria2", "tuic")


import concurrent.futures  # noqa: E402
import socket  # noqa: E402

_dns = {}


def resolve_all(hosts):
    def one(h):
        try:
            return h, socket.getaddrinfo(h, None, socket.AF_INET)[0][4][0]
        except (OSError, IndexError, UnicodeError):
            return h, None
    socket.setdefaulttimeout(3)
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as ex:
        for h, ip in ex.map(one, hosts):
            _dns[h] = ip


def server_country(e):
    h = e.p.host.strip("[]")
    try:
        ipaddress.ip_address(h)
        ip = h
    except ValueError:
        ip = _dns.get(h)
    return geo.country(ip) if (geo is not None and ip) else ""


safe_candidates = [e for e in main if encrypted_and_verified(e.p) and e.flag not in ("🇷🇺", "🌐")]
resolve_all(sorted({e.p.host for e in safe_candidates if not e.p.host.startswith("[") and not e.p.host[0].isdigit()}))
safe = [e for e in safe_candidates if server_country(e) != "RU"]
safe.sort(key=order_key)

# ---- 4в. «максимальное доверие»: VLESS Reality напрямую (ключ сервера зашит в конфиг, без CDN-посредников),
# проверено из РФ или подтверждено 4+ независимыми источниками, страна известна и не из стран с обязательной
# прослушкой трафика; один вариант на сервер
SURVEILLANCE = {"RU", "BY", "CN", "IR", "KZ"}
trusted, seen_backend = [], set()
for e in sorted(safe, key=lambda e: (-score(e), e.order)):
    q = query_dict(e.p.link_body.split("?", 1)[1]) if e.p.link_body and "?" in e.p.link_body else {}
    if e.p.scheme != "vless" or q.get("security", "").lower() != "reality":
        continue
    if not (e.owners & TESTED_IN_RU or len(e.owners) >= 4):
        continue
    if flag_to_cc(e.flag) in SURVEILLANCE or server_country(e) in SURVEILLANCE:
        continue
    bk = backend_key(e.p)
    if bk in seen_backend:
        continue
    seen_backend.add(bk)
    trusted.append(e)
trusted.sort(key=order_key)

# ---- 5. запись ------------------------------------------------------------------------------
now = datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=3)))
stamp = now.strftime("%d.%m.%Y %H:%M МСК")


def b64(s):
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


def write_sub(lst, fname, title, with_b64):
    links = [render(e.p, f"{e.flag} {e.p.proto_label} · {mode(e)} · {i:04d}") for i, e in enumerate(lst, 1)]
    header = [
        "#profile-title: base64:" + b64(title),
        "#profile-update-interval: 3",
        "#announce: base64:" + b64(f"Обновлено {stamp} · {len(links)} серверов · ЧС — обычный режим, БС — белые списки"),
    ]
    if REPO:
        header.append(f"#profile-web-page-url: https://github.com/{REPO}")
    with open(os.path.join(OUT, fname + ".txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(header + links) + "\n")
    if with_b64:
        with open(os.path.join(OUT, fname + "-base64.txt"), "w", encoding="ascii") as f:
            f.write(b64("\n".join(links) + "\n"))
    return len(links)


n_main = write_sub(main, "ru-vpn", "RU VPN · основная", True)
n_full = write_sub(full, "ru-vpn-full", "RU VPN · полная", False)
n_safe = write_sub(safe, "ru-vpn-safe", "RU VPN · минимальный риск", False)
n_trusted = write_sub(trusted, "ru-vpn-trusted", "RU VPN · максимальное доверие", False)
modes_main = collections.Counter(mode(e) for e in main)
with open(os.path.join(OUT, "README.md"), "w", encoding="utf-8") as f:
    f.write(f"# Подписка обновлена {stamp}\n\n"
            f"- `ru-vpn.txt` — основная: {n_main} (ЧС {modes_main['ЧС']}, БС {modes_main['БС']})\n"
            f"- `ru-vpn-base64.txt` — то же в base64\n"
            f"- `ru-vpn-trusted.txt` — максимальное доверие: {n_trusted}\n"
            f"- `ru-vpn-safe.txt` — минимальный риск для личного пользования: {n_safe}\n"
            f"- `ru-vpn-full.txt` — всё подряд: {n_full}\n")
print(f"unique: {len(entries)} | main: {n_main} {dict(modes_main)} | safe: {n_safe} | trusted: {n_trusted} | full: {n_full} | "
      f"whitelist ranges: {len(merged)}, domains: {len(wl_domains)}, geoip: {'yes' if geo else 'no'}, "
      f"dns resolved: {sum(1 for v in _dns.values() if v)}/{len(_dns)}")
