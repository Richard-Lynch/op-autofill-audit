#!/usr/bin/env python3
"""Find 1Password items whose website autofill is NOT "only fill on this exact domain".

For every item with a website on --domain (or a subdomain of it), report each such
website's autofill behaviour. Read-only, and prints titles, vault names and URLs only;
no field values are ever requested.

    ./audit.py                 # first run creates .venv, installs deps, offers to write .env
    ./audit.py --setup         # (re)create .env interactively from .env.example
    ./audit.py --domain example.com --account my.1password.com

Auth is the 1Password desktop-app integration (Settings > Developer > "Integrate with
the 1Password SDKs"), which is the only SDK auth that can see personal vaults.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import subprocess
import sys
from typing import NamedTuple
from urllib.parse import urlparse

EXACT = "ExactDomain"
MIN_PYTHON = (3, 10)  # the SDK evaluates `X | Y` annotations at import time
SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://")
HERE = os.path.dirname(os.path.abspath(__file__))
ENV_FILE = os.path.join(HERE, ".env")
ENV_TEMPLATE = os.path.join(HERE, ".env.example")
VENV_DIR = os.path.join(HERE, ".venv")
REQUIREMENTS = os.path.join(HERE, "requirements.txt")
BOOTSTRAPPED = "AUDIT_BOOTSTRAPPED"  # set across the re-exec so it can never loop


# --- bootstrap: make `./audit.py` work from a bare clone (stdlib only) ---------------


def _venv_python() -> str:
    sub = "Scripts" if os.name == "nt" else "bin"
    return os.path.join(VENV_DIR, sub, "python" + (".exe" if os.name == "nt" else ""))


def _log(msg: str) -> None:
    print(f"[audit] {msg}", file=sys.stderr)


def bootstrap() -> None:
    """Ensure .venv exists with the requirements installed, then re-exec inside it.

    Runs `pip install -r requirements.txt` every time: a no-op when satisfied, and it repairs
    a venv holding an out-of-range SDK, which an import check would accept. Skipped when the
    guard is set. Any failure is reported with the manual command, rather than carrying on to
    an ImportError further down."""
    if sys.version_info < MIN_PYTHON:
        raise SystemExit(f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ is required, found {sys.version.split()[0]}")
    if os.environ.get(BOOTSTRAPPED):
        return
    py = _venv_python()
    try:
        if not os.path.exists(py):
            _log("first run: creating .venv")
            subprocess.run([sys.executable, "-m", "venv", VENV_DIR], check=True)
        pip = [py, "-m", "pip", "install", "-q", "--disable-pip-version-check", "-r", REQUIREMENTS]
        subprocess.run(pip, check=True)
    except (subprocess.CalledProcessError, OSError) as exc:
        raise SystemExit(
            f"venv setup failed ({exc}). Do it by hand:\n"
            f"  python3 -m venv .venv && .venv/bin/pip install -r requirements.txt"
        )
    if os.path.realpath(sys.prefix) != os.path.realpath(VENV_DIR):
        os.environ[BOOTSTRAPPED] = "1"
        os.execv(py, [py, os.path.abspath(__file__), *sys.argv[1:]])


# --- .env handling ---------------------------------------------------------------------


class Entry(NamedTuple):
    key: str
    example: str
    help: str


def read_env_file(path: str) -> dict:
    """KEY=VALUE pairs from a .env file; {} if absent. Blank lines and `#` comments are
    skipped; `export ` prefixes and one pair of surrounding quotes are stripped."""
    try:
        lines = open(path, encoding="utf-8").read().splitlines()
    except FileNotFoundError:
        return {}
    out = {}
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip().removeprefix("export ").strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        out[key] = value
    return out


def parse_template(text: str) -> list[Entry]:
    """Entries from a .env.example. Comment lines directly above a KEY=value line are
    its help text; a blank line ends a comment block (so a file header isn't attached)."""
    entries, help_lines = [], []
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("#"):
            help_lines.append(line.lstrip("#").strip())
        elif not line:
            help_lines = []
        elif "=" in line:
            key, _, example = line.partition("=")
            entries.append(Entry(key.strip(), example.strip(), " ".join(help_lines)))
            help_lines = []
    return entries


def render_env(entries: list[Entry], values: dict) -> str:
    out = ["# Local config, gitignored. Real environment variables override these."]
    for e in entries:
        out.append("")
        if e.help:
            out.append(f"# {e.help}")
        v = values[e.key]
        out.append(f'{e.key}="{v}"' if any(c in v for c in " #\t") else f"{e.key}={v}")
    return "\n".join(out) + "\n"


def _err(*args) -> None:
    """Interactive text goes to stderr so `--json > file` stays parseable."""
    print(*args, file=sys.stderr)


def _ask(prompt: str) -> str:
    print(prompt, end="", file=sys.stderr, flush=True)
    return input()


def setup(
    template: str = ENV_TEMPLATE,
    env_path: str = ENV_FILE,
    ask=None,
    out=None,
) -> dict:
    """Interactively write env_path from the template. Existing values are the defaults
    (Enter keeps them); the template's example values are hints only and never accepted
    as answers, because a placeholder in .env would look configured and not be."""
    ask = ask or _ask  # resolved at call time so tests can patch builtins.input
    out = out or _err
    try:
        entries = parse_template(open(template, encoding="utf-8").read())
    except FileNotFoundError:
        raise SystemExit(f"template not found: {template}")
    if not entries:
        raise SystemExit(f"no KEY=value lines in {template}")
    current = read_env_file(env_path)
    if current:
        out(f"Existing {os.path.basename(env_path)} found: Enter keeps the current value.")
    values = {}
    for e in entries:
        if e.help:
            out(f"\n{e.help}")
        while True:
            default = current.get(e.key, "")
            hint = f"[{default}]" if default else f"(e.g. {e.example})"
            answer = ask(f"{e.key} {hint}: ").strip() or default
            if answer:
                values[e.key] = answer
                break
            out("  a value is required")
    fd = os.open(env_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(render_env(entries, values))
    os.chmod(env_path, 0o600)  # O_CREAT's mode is ignored for a pre-existing file
    out(f"\nWrote {env_path} (mode 600, gitignored).")
    return values


# --- the audit -------------------------------------------------------------------------


def host_of(url: str) -> str:
    """Hostname of a stored URL; tolerates a missing scheme. Raises ValueError if malformed."""
    url = url.strip()
    if not (SCHEME.match(url) or url.startswith("//")):
        url = "//" + url
    return (urlparse(url).hostname or "").lower().rstrip(".")


def normalize_domain(raw: str) -> str:
    """'*.Example.com.' -> 'example.com'. Rejects URLs, ports, paths and stray wildcards,
    which would otherwise match nothing and read as a clean report."""
    domain = raw.strip().lower().removeprefix("*.").removesuffix(".")
    if not domain or any(c in domain for c in "/:*@?# "):
        raise ValueError(f"expected a bare domain such as example.com, got {raw!r}")
    return domain


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
        try:
            if on_domain(host_of(site.url), domain):
                out.append({"url": site.url, "behaviour": behaviour_name(site.autofill_behavior)})
        except ValueError:  # can't tell whether it is on the domain: show it, never skip it
            out.append({"url": site.url, "behaviour": "UnparseableURL"})
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


def resolve_config(args) -> tuple:
    """(account, domain): flag > real environment variable > .env. Blank values count as unset."""
    cfg = {k: v for k, v in {**read_env_file(ENV_FILE), **os.environ}.items() if v}
    return args.account or cfg.get("OP_ACCOUNT_NAME"), args.domain or cfg.get("OP_AUDIT_DOMAIN")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--domain", help="e.g. example.com, matches subdomains (or OP_AUDIT_DOMAIN)")
    ap.add_argument("--account", help="1Password account name or address (or OP_ACCOUNT_NAME)")
    ap.add_argument("--setup", action="store_true", help="write .env interactively and exit")
    ap.add_argument("--all", action="store_true", help="also list items already exact-domain")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    if args.setup:
        setup(ENV_TEMPLATE, ENV_FILE)
        return 0

    account, domain = resolve_config(args)
    if (not account or not domain) and sys.stdin.isatty():
        _err("Missing configuration; let's set it up.\n")
        setup(ENV_TEMPLATE, ENV_FILE)
        account, domain = resolve_config(args)
    if not account:
        ap.error("--account (or OP_ACCOUNT_NAME) is required; try --setup")
    if not domain:
        ap.error("--domain (or OP_AUDIT_DOMAIN) is required; try --setup")
    try:
        domain = normalize_domain(domain)
    except ValueError as exc:
        ap.error(str(exc))

    rows, seen = asyncio.run(collect(account, domain))
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
    bootstrap()
    sys.exit(main())
