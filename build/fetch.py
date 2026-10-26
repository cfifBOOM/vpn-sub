"""Скачивает все источники из sources.py в папку (по умолчанию _src)."""
import concurrent.futures
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sources import SOURCES, WHITELIST_CIDR, WHITELIST_SNI, GEOIP_MMDB  # noqa: E402

RAW_BASE = os.environ.get("RAW_BASE", "https://raw.githubusercontent.com").rstrip("/")
DEST = sys.argv[1] if len(sys.argv) > 1 else "_src"


def local_path(repo, path):
    repo = repo.split("@", 1)[0]
    return os.path.join(DEST, repo.replace("/", "__"), path)


def url_for(repo, path):
    ref = "HEAD"
    if "@" in repo:
        repo, ref = repo.split("@", 1)
    return f"{RAW_BASE}/{repo}/{ref}/{urllib.parse.quote(path, safe='/')}"


def fetch(item):
    repo, path = item[0], item[1]
    url = url_for(repo, path)
    dst = local_path(repo, path)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    last = None
    for attempt in range(3):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (vpn-sub builder)"})
            with urllib.request.urlopen(req, timeout=60) as r:
                data = r.read()
            with open(dst, "wb") as f:
                f.write(data)
            return repo, path, len(data), None
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            last = e
            if isinstance(e, urllib.error.HTTPError) and e.code == 404:
                break
            time.sleep(2 * (attempt + 1))
    return repo, path, 0, str(last)


def main():
    items = [(r, p) for r, p, _ in SOURCES] + list(WHITELIST_CIDR) + list(WHITELIST_SNI)
    ok = failed = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        for repo, path, size, err in ex.map(fetch, items):
            if err:
                failed += 1
                print(f"FAIL {repo}/{path}: {err}")
            else:
                ok += 1
                print(f"ok   {repo}/{path} ({size // 1024} KB)")
    for repo, path in GEOIP_MMDB:
        _, _, size, err = fetch((repo, path))
        if not err and size > 100_000:
            print(f"ok   GeoIP from {repo} ({size // 1024} KB)")
            with open(os.path.join(DEST, "geoip.path"), "w") as f:
                f.write(os.path.relpath(local_path(repo, path), DEST))
            break
        print(f"FAIL GeoIP {repo}: {err}")
    print(f"downloaded {ok}/{ok + failed}")
    if ok < (ok + failed) / 2:
        sys.exit("слишком много источников недоступно — публикацию пропускаем")


if __name__ == "__main__":
    main()
