#!/usr/bin/env python3
"""Ethical passive OSINT for domains; uses public technical sources only."""
from __future__ import annotations

import argparse
import json
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any

USER_AGENT = "OSINT-Toolkit/1.0 (ethical passive domain research)"


def clean_domain(value: str) -> str:
    value = value.strip()
    if "://" in value:
        value = urllib.parse.urlparse(value).hostname or ""
    value = value.rstrip(".").lower()
    if not value or "/" in value or " " in value or "." not in value:
        raise ValueError("Enter a valid domain, such as example.com (not a URL path).")
    if len(value) > 253:
        raise ValueError("Domain is too long.")
    return value


def dns_lookup(domain: str) -> dict[str, Any]:
    """Resolve common DNS record types using available system tools."""
    result: dict[str, Any] = {}
    try:
        infos = socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
        result["A_or_AAAA"] = sorted({item[4][0] for item in infos})
    except socket.gaierror as exc:
        result["A_or_AAAA_error"] = str(exc)

    # Python's standard library has no general DNS TXT/MX/NS API.
    # Keep the script dependency-free and explain this limitation.
    result["note"] = (
        "This standard-library version resolves host addresses only. "
        "MX, NS, and TXT records require a DNS library such as dnspython."
    )
    return result


def fetch_json(url: str, timeout: int = 12) -> Any:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        if response.status != 200:
            raise RuntimeError(f"HTTP status {response.status}")
        return json.loads(response.read(2_000_000).decode("utf-8", errors="replace"))


def rdap_lookup(domain: str) -> dict[str, Any]:
    url = "https://rdap.org/domain/" + urllib.parse.quote(domain, safe=".-")
    try:
        data = fetch_json(url)
        events = data.get("events", [])
        nameservers = [
            item.get("ldhName")
            for item in data.get("nameservers", [])
            if item.get("ldhName")
        ]
        return {
            "source": url,
            "domain": data.get("ldhName", domain),
            "status": data.get("status", []),
            "events": [
                {"action": event.get("eventAction"), "date": event.get("eventDate")}
                for event in events
            ],
            "nameservers": nameservers,
            "note": "Registration data may be redacted, incomplete, or delayed.",
        }
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, RuntimeError) as exc:
        return {"source": url, "error": str(exc)}


def certificate_transparency_lookup(domain: str) -> dict[str, Any]:
    # Exact-domain query only; do not enumerate arbitrary subdomains.
    url = "https://crt.sh/?q=" + urllib.parse.quote(domain, safe=".-") + "&output=json"
    try:
        data = fetch_json(url)
        entries = []
        seen = set()
        for item in data if isinstance(data, list) else []:
            name = item.get("name_value", "")
            key = (name, item.get("not_before"), item.get("not_after"))
            if key in seen:
                continue
            seen.add(key)
            entries.append({
                "name": name,
                "issuer": item.get("issuer_name"),
                "not_before": item.get("not_before"),
                "not_after": item.get("not_after"),
            })
        return {
            "source": url,
            "entry_count": len(entries),
            "certificates": entries[:100],
            "truncated": len(entries) > 100,
            "note": "Certificate records show certificate issuance, not proof of current control.",
        }
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, RuntimeError) as exc:
        return {"source": url, "error": str(exc)}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Ethical passive OSINT for a domain you own or are authorized to assess."
    )
    parser.add_argument("domain", help="Domain name, e.g. example.com")
    parser.add_argument("--output", "-o", help="Write results to a JSON file")
    args = parser.parse_args()

    try:
        domain = clean_domain(args.domain)
    except ValueError as exc:
        parser.error(str(exc))

    report = {
        "tool": "OSINT Toolkit",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "target_domain": domain,
        "scope": "Passive public technical information only",
        "dns": dns_lookup(domain),
        "rdap": rdap_lookup(domain),
        "certificate_transparency": certificate_transparency_lookup(domain),
        "limitations": [
            "Data may be incomplete, stale, or affected by network conditions.",
            "A shared IP address or certificate does not prove common ownership.",
            "Use only for lawful, authorized research.",
        ],
    }

    rendered = json.dumps(report, indent=2, ensure_ascii=False)
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as handle:
                handle.write(rendered + "\n")
            print(f"Report saved to {args.output}")
        except OSError as exc:
            print(f"Could not write output file: {exc}", file=sys.stderr)
            return 1
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
