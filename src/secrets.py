#!/usr/bin/env python3
"""
04_secrets.py
Scans all text-readable files for hardcoded credentials,
API keys, tokens, and other secrets using regex patterns.
"""
import json
import os
import re
import subprocess
import sys
from pathlib import Path


PATTERNS = [
    # Cloud / SaaS
    ("aws_access_key",         "critical", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("aws_secret_key",         "critical", re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"]([A-Za-z0-9/+]{40})['\"]")),
    ("google_oauth_secret",    "critical", re.compile(r"GOCSPX-[A-Za-z0-9_-]+")),
    ("google_api_key",         "high",     re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("github_token",           "critical", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("stripe_secret",          "critical", re.compile(r"sk_live_[A-Za-z0-9]{24,}")),
    ("stripe_publishable",     "low",      re.compile(r"pk_live_[A-Za-z0-9]{24,}")),

    # Auth / tokens
    ("jwt",                    "high",     re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")),
    ("bearer_token",           "high",     re.compile(r"(?i)bearer\s+[A-Za-z0-9_\-\.]{20,}")),

    # Monitoring / analytics
    ("sentry_dsn",             "medium",   re.compile(r"https://[a-f0-9]{32}@[a-z0-9.]*sentry\.io/\d+")),
    ("posthog_key",            "medium",   re.compile(r"phc_[A-Za-z0-9]{30,}")),

    # Backend / DB
    ("supabase_anon_key",      "low",      re.compile(r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]+")),
    ("supabase_service_role",  "critical", re.compile(r"(?i)service.?role.{0,30}eyJ[A-Za-z0-9_-]+")),
    ("postgres_url",           "high",     re.compile(r"postgres(?:ql)?://[^'\"\s]+")),
    ("mongodb_url",            "high",     re.compile(r"mongodb(?:\+srv)?://[^'\"\s]+")),

    # Private keys
    ("private_key_pem",        "critical", re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")),
    ("ssh_private_key",        "critical", re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----")),

    # Generic high-entropy patterns
    ("generic_secret",         "medium",   re.compile(r"(?i)(?:secret|api.?key|api.?secret|access.?token)\s*[=:]\s*['\"]([A-Za-z0-9_\-]{20,})['\"]")),
    ("cloudflare_token",       "high",     re.compile(r"(?i)cloudflare.{0,30}['\"]([A-Za-z0-9_-]{37})['\"]")),
]

# Extensions to skip (binary, media, etc.)
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".icns", ".car",
    ".mp3", ".mp4", ".mov", ".wav",
    ".dylib", ".so", ".a",
    ".nib", ".xib",
    ".zip", ".gz", ".tar",
    ".ttf", ".otf", ".woff",
    ".sqlite", ".db",
}

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB — skip large binaries


def is_readable_text(path: Path) -> bool:
    if path.suffix.lower() in SKIP_EXTENSIONS:
        return False
    if path.stat().st_size > MAX_FILE_SIZE:
        return False
    try:
        with open(path, "rb") as f:
            chunk = f.read(512)
        # Heuristic: if >30% non-printable bytes, treat as binary
        non_printable = sum(1 for b in chunk if b < 9 or (13 < b < 32) or b > 126)
        return (non_printable / max(len(chunk), 1)) < 0.30
    except Exception:
        return False


def scan_file(path: Path, root: Path) -> list[dict]:
    findings = []
    try:
        content = path.read_text(errors="replace")
    except Exception:
        return findings

    rel = str(path.relative_to(root))

    for pattern_name, severity, pattern in PATTERNS:
        for match in pattern.finditer(content):
            matched = match.group(0)
            preview = matched[:80] + "..." if len(matched) > 80 else matched
            # Get line number
            line_no = content[:match.start()].count("\n") + 1
            findings.append({
                "type": pattern_name,
                "severity": severity,
                "location": rel,
                "line": line_no,
                "value_preview": preview,
            })

    return findings


def analyze(extract_dir: str, output_path: str) -> None:
    root = Path(extract_dir)
    all_findings = []

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if not is_readable_text(path):
            continue
        findings = scan_file(path, root)
        all_findings.extend(findings)

    # Deduplicate by (type, value_preview)
    seen = set()
    deduped = []
    for f in all_findings:
        key = (f["type"], f["value_preview"])
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    deduped.sort(key=lambda x: severity_order.get(x["severity"], 9))

    result = {
        "total_findings": len(deduped),
        "by_severity": {
            "critical": [f for f in deduped if f["severity"] == "critical"],
            "high":     [f for f in deduped if f["severity"] == "high"],
            "medium":   [f for f in deduped if f["severity"] == "medium"],
            "low":      [f for f in deduped if f["severity"] == "low"],
        },
        "findings": deduped,
    }

    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)


if __name__ == "__main__":
    analyze(sys.argv[1], sys.argv[2])
