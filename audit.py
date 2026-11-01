#!/usr/bin/env python3
"""Find 1Password items whose website autofill is NOT "only fill on this exact domain".

For every item with a website on --domain (or a subdomain of it), report each such
website's autofill behaviour. Read-only, and prints titles, vault names and URLs only;
no field values are ever requested.

    .venv/bin/python audit.py --domain example.com --account my.1password.com

Auth is the 1Password desktop-app integration (Settings > Developer > "Integrate with
the 1Password SDKs"), which is the only SDK auth that can see personal vaults.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from urllib.parse import urlparse

EXACT = "ExactDomain"


def host_of(url: str) -> str:
    """Hostname of a stored URL; tolerates entries saved without a scheme."""
    parsed = urlparse(url if "://" in url else f"//{url}")
    return (parsed.hostname or "").lower()


def on_domain(host: str, domain: str) -> bool:
    """True for the domain itself or a subdomain. 'notexample.com' must not match."""
    return host == domain or host.endswith("." + domain)


def behaviour_name(value) -> str:
    """Enum or plain string -> its string value; anything unreadable is 'Unknown'."""
    return str(getattr(value, "value", value)) if value is not None else "Unknown"


def classify(websites, domain: str) -> list[dict]:
    """Websites on `domain`, each with its behaviour. `websites` are objects with
    .url and .autofill_behavior (the SDK's Website type)."""
    out = []
    for site in websites or []:
        if on_domain(host_of(site.url), domain):
            out.append({"url": site.url, "behaviour": behaviour_name(site.autofill_behavior)})
    return out


def not_exact(sites: list[dict]) -> list[dict]:
    """Matching websites whose behaviour is anything other than exact-domain.
    'Unknown' is kept: an unreadable setting must not read as 'fine'."""
    return [s for s in sites if s["behaviour"] != EXACT]


async def collect(account: str, domain: str) -> tuple[list[dict], int]:
    from onepassword import Client, DesktopAuth

    client = await Client.authenticate(
        auth=DesktopAuth(account_name=account),
        integration_name="op-autofill-audit",
        integration_version="0.1.0",
    )
    vaults = await client.vaults.list()
    if not vaults:
        raise SystemExit("no vaults visible: wrong account or integration not enabled")
    rows, seen = [], 0
    for vault in vaults:
        for item in await client.items.list(vault.id):
            seen += 1
            sites = classify(item.websites, domain)
            if sites:
                rows.append(
                    {"vault": vault.title, "title": item.title, "id": item.id, "sites": sites}
                )
    return rows, seen


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--domain", required=True, help="e.g. example.com (matches subdomains too)")
    ap.add_argument(
        "--account",
        default=os.environ.get("OP_ACCOUNT_NAME"),
        help="1Password account name or sign-in address (or set OP_ACCOUNT_NAME)",
    )
    ap.add_argument("--all", action="store_true", help="also list items already exact-domain")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()
    if not args.account:
        ap.error("--account (or OP_ACCOUNT_NAME) is required")

    domain = args.domain.lower().lstrip("*.")
    rows, seen = asyncio.run(collect(args.account, domain))
    # Zero items scanned means we saw nothing, not that nothing matches.
    if seen == 0:
        print("scanned zero items: not a clean result", file=sys.stderr)
        return 2

    report = []
    for row in rows:
        shown = row["sites"] if args.all else not_exact(row["sites"])
        if shown:
            report.append({**row, "sites": shown})

    if args.json:
        json.dump(report, sys.stdout, indent=2)
        print()
    else:
        for row in sorted(report, key=lambda r: (r["vault"], r["title"])):
            for s in row["sites"]:
                print(f"{row['vault']}\t{row['title']}\t{s['behaviour']}\t{s['url']}")
    print(
        f"{len(report)} of {len(rows)} items on *.{domain} reported; {seen} items scanned",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
