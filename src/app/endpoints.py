#!/usr/bin/env python3
import ipaddress
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

from utils.log import get_logger, setup

log = get_logger("endpoints")


URL_PATTERN = re.compile(r"https?://[a-zA-Z0-9._\-/:%?=&@#~+]+")
WSS_PATTERN = re.compile(r"wss?://[a-zA-Z0-9._\-/:%?=&@#~+]+")
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b")
DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|io|dev|app|net|org|co|ai|cloud|workers\.dev|supabase\.co|sentry\.io)\b"
)

SKIP_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".icns",
    ".car",
    ".mp3",
    ".mp4",
    ".mov",
    ".wav",
    ".dylib",
    ".so",
    ".a",
    ".nib",
    ".xib",
    ".zip",
    ".gz",
    ".tar",
    ".ttf",
    ".otf",
    ".sqlite",
    ".db",
}

MAX_FILE_SIZE = 5 * 1024 * 1024

TRACKING_DOMAINS = {
    "posthog.com",
    "us.i.posthog.com",
    "sentry.io",
    "mixpanel.com",
    "amplitude.com",
    "segment.io",
    "segment.com",
    "datadog.com",
    "newrelic.com",
    "analytics.google.com",
    "doubleclick.net",
    "hotjar.com",
    "fullstory.com",
    "logrocket.com",
}

THIRD_PARTY_AI = {
    "api.anthropic.com",
    "api.openai.com",
    "openrouter.ai",
    "api.assemblyai.com",
    "streaming.assemblyai.com",
    "api.cohere.com",
    "api.mistral.ai",
}


def is_valid_ip(s: str) -> bool:
    """Return True if the string is a routable (non-loopback, non-private) IP address."""
    ip = s.split(":")[0]
    try:
        addr = ipaddress.ip_address(ip)
        return not addr.is_loopback and not addr.is_private and not addr.is_link_local
    except ValueError:
        return False


def is_readable(path: Path) -> bool:
    """Return True if the file is small enough and appears to be text (heuristic byte scan)."""
    if path.suffix.lower() in SKIP_EXTENSIONS:
        return False
    if path.stat().st_size > MAX_FILE_SIZE:
        return False
    try:
        with path.open("rb") as f:
            chunk = f.read(512)
        non_printable = sum(1 for b in chunk if b < 9 or (13 < b < 32) or b > 126)
        return (non_printable / max(len(chunk), 1)) < 0.30
    except (OSError, PermissionError) as e:
        log.debug("cannot read %s: %s", path.name, e)
        return False


def analyze(extract_dir: str, output_path: str) -> None:
    """Scan all text files for URLs, IPs, and domains; classify tracking and AI API endpoints."""
    setup()
    log.info("starting")
    root = Path(extract_dir)

    all_urls = set()
    all_wss = set()
    all_ips = set()
    all_domains = set()

    for path in root.rglob("*"):
        if not path.is_file() or not is_readable(path):
            continue
        try:
            content = path.read_text(errors="replace")
        except (OSError, PermissionError) as e:
            log.debug("skipping %s: %s", path.name, e)
            continue

        all_urls.update(URL_PATTERN.findall(content))
        all_wss.update(WSS_PATTERN.findall(content))
        all_domains.update(DOMAIN_PATTERN.findall(content))

        for ip_match in IP_PATTERN.findall(content):
            if is_valid_ip(ip_match):
                all_ips.add(ip_match)

    tracking = []
    ai_apis = []
    other = []

    for url in sorted(all_urls):
        try:
            host = urlparse(url).netloc.lower().removeprefix("www.")
        except ValueError as e:
            log.debug("url parse error %s: %s", url[:60], e)
            host = ""
        entry = {"url": url, "host": host}

        if any(t in host for t in TRACKING_DOMAINS):
            tracking.append(entry)
        elif any(a in host for a in THIRD_PARTY_AI):
            ai_apis.append(entry)
        else:
            other.append(entry)

    if tracking:
        log.warning("tracking endpoints: %d", len(tracking))
    if ai_apis:
        log.info("AI API endpoints: %d", len(ai_apis))

    log.info(
        "urls=%d wss=%d ips=%d domains=%d",
        len(all_urls),
        len(all_wss),
        len(all_ips),
        len(all_domains),
    )

    result = {
        "summary": {
            "total_urls": len(all_urls),
            "websocket_urls": len(all_wss),
            "external_ips": len(all_ips),
            "tracking_services": len(tracking),
            "ai_api_endpoints": len(ai_apis),
        },
        "tracking_services": tracking,
        "ai_api_endpoints": ai_apis,
        "websocket_urls": sorted(all_wss),
        "external_ips": sorted(all_ips),
        "all_urls": sorted(other, key=lambda x: x["url"]),
        "all_domains": sorted(all_domains),
    }

    with Path(output_path).open("w") as f:
        json.dump(result, f, indent=2)
    log.info("done")


if __name__ == "__main__":
    analyze(sys.argv[1], sys.argv[2])
