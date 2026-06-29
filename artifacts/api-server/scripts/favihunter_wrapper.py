#!/usr/bin/env python3
"""
favihunter_wrapper.py — Sentinelware CTEM Platform
Uses the favihunter library to compute real favicon hashes (MMH3/MD5/SHA256)
and generates search-engine pivot URLs for Shodan, Censys, FOFA, etc.
Outputs JSON to stdout. Takes a domain or full URL as argv[1].
"""
import sys
import json
from base64 import b64encode, encodebytes, b64decode
from hashlib import md5, sha256
from urllib.parse import urlparse
from pathlib import Path

PYTHONLIBS = "/home/runner/workspace/.pythonlibs/lib/python3.11/site-packages"
if PYTHONLIBS not in sys.path:
    sys.path.insert(0, PYTHONLIBS)

try:
    from mmh3 import hash as mmh3_calc
    from requests import get as http_get
    from requests.exceptions import RequestException, Timeout
    from favicon import get as get_favicons
    from yaml import safe_load
except ImportError as e:
    sys.stdout.write(json.dumps({"error": f"Missing dependency: {e}. Run: pip install favihunter"}))
    sys.exit(1)

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "*/*",
    "Cache-Control": "no-cache",
}

ENGINES_YAML = Path(PYTHONLIBS) / "favihunter" / "engines.yaml"


def calculate_mmh3(data: bytes) -> int:
    encoded = encodebytes(data)
    return mmh3_calc(encoded)


def convert_fofa_query(mmh3_hash: int) -> str:
    query = f'icon_hash="{mmh3_hash}"'.encode("utf-8")
    return b64encode(query).decode("utf-8")


def mmh3_to_hex(val: int) -> str:
    raw = hex(val)
    if raw.startswith("-"):
        raw = raw[3:]
    elif raw.startswith("0x"):
        raw = raw[2:]
    return raw or "0"


def resolve_favicon_url(url: str):
    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    ico_url = f"{origin}/favicon.ico"
    try:
        r = http_get(ico_url, headers=HEADERS, timeout=8, stream=True)
        ctype = (r.headers.get("content-type") or "").lower()
        if r.ok and ("image" in ctype or "octet-stream" in ctype or "x-icon" in ctype):
            return ico_url
    except (RequestException, Timeout):
        pass

    try:
        favs = get_favicons(url=url, headers=HEADERS, timeout=8)
        # Prefer non-data-URI .ico favicons
        for f in favs:
            if not f.url.startswith("data:") and f.url.lower().endswith(".ico"):
                return f.url
        # Fall back to any non-data-URI favicon
        for f in favs:
            if not f.url.startswith("data:"):
                return f.url
        # Fall back to a data URI only if it has actual content (>50 chars after comma)
        for f in favs:
            if f.url.startswith("data:") and "," in f.url:
                payload = f.url.split(",", 1)[1]
                if len(payload) > 50:
                    return f.url
    except Exception:
        pass

    return None


def fetch_favicon_bytes(fav_url: str):
    """Download favicon bytes. Handles both http(s):// and data: URIs."""
    if fav_url.startswith("data:"):
        # data:[<mediatype>][;base64],<data>
        try:
            header, encoded = fav_url.split(",", 1)
            if "base64" in header:
                return b64decode(encoded + "==")  # padding-safe
            else:
                return encoded.encode("utf-8")
        except Exception as e:
            return None, f"Failed to decode data URI: {e}"

    resp = http_get(fav_url, headers=HEADERS, timeout=15)
    if not resp.ok:
        return None
    return resp.content if resp.content else None


def build_search_urls(hashes: dict) -> dict:
    try:
        with open(ENGINES_YAML) as f:
            engines = safe_load(f)
        urls = {}
        for _key, info in engines.items():
            name = info.get("name")
            if name == "VirusTotal":
                continue
            hash_key = info.get("hash")
            val = hashes.get(hash_key)
            if val is None:
                continue
            if name == "FOFA":
                q = convert_fofa_query(int(val))
                url = info["url"].format(q)
            else:
                url = info["url"].format(val)
            urls[name] = {"url": url, "hash_type": hash_key}
        return urls
    except Exception as e:
        return {"_error": str(e)}


def main():
    if len(sys.argv) < 2:
        sys.stdout.write(json.dumps({"error": "Usage: favihunter_wrapper.py <domain_or_url>"}))
        sys.exit(1)

    raw = sys.argv[1].strip()
    url = raw if raw.startswith("http") else f"https://{raw}"

    fav_url = resolve_favicon_url(url)
    if not fav_url:
        sys.stdout.write(json.dumps({"error": f"No favicon found for {url}"}))
        sys.exit(0)

    try:
        content = fetch_favicon_bytes(fav_url)
        if not content:
            sys.stdout.write(json.dumps({
                "error": f"Failed to download favicon from {fav_url}"
            }))
            sys.exit(0)

        mmh3_val = calculate_mmh3(content)
        mmh3_hex = mmh3_to_hex(mmh3_val)
        md5_val = md5(content).hexdigest()
        sha256_val = sha256(content).hexdigest()

        hashes = {
            "MMH3": mmh3_val,
            "MMH3-HEX": mmh3_hex,
            "MD5": md5_val,
            "SHA256": sha256_val,
        }

        search_urls = build_search_urls(hashes)

        # NOTE: hash keys use camelCase to match the TypeScript FaviHunterResult interface
        sys.stdout.write(json.dumps({
            "favicon_url": fav_url,
            "hashes": {
                "mmh3": mmh3_val,
                "mmh3Hex": mmh3_hex,
                "md5": md5_val,
                "sha256": sha256_val,
            },
            "search_urls": search_urls,
        }))

    except Exception as e:
        sys.stdout.write(json.dumps({"error": str(e)}))
        sys.exit(1)


if __name__ == "__main__":
    main()
