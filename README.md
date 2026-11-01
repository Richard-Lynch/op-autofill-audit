# op-autofill-audit

List 1Password items on a domain (and its subdomains) whose website autofill is **not**
set to "only fill on this exact domain" -- i.e. the default "fill anywhere on the website,
including subdomains", or "never".

The `op` CLI cannot read this per-URL setting; the 1Password SDK can, so this uses the SDK.

## Safety

- Read-only. It lists items and reads their website entries; it never requests field values
  (passwords, OTPs, notes).
- Prints vault, item title, behaviour and URL to your terminal. Nothing is written to disk
  and nothing is sent anywhere except to your local 1Password app.
- Output names real items, so don't paste it into public places. `.gitignore` blocks
  `*.json`/`*.csv`/`*.1pux` for that reason.

## Setup

1. In the 1Password desktop app: Settings > Developer > enable
   "Integrate with the 1Password SDKs". This is the only SDK auth that can see personal vaults
   (service accounts cannot).
2. `python3 -m venv .venv && .venv/bin/pip install -r requirements.txt`

## Use

```
.venv/bin/python audit.py --domain example.com --account my.1password.com
```

`--account` is your account name or sign-in address; `--domain` is the site to audit. Both can
instead live in a gitignored `.env` (copy `.env.example`): `OP_ACCOUNT_NAME`, `OP_AUDIT_DOMAIN`.
Real environment variables and flags override the file.
Approve the prompt in the 1Password app (access lapses after 10 minutes idle).

| flag | effect |
|---|---|
| `--all` | also show websites already set to exact-domain |
| `--json` | machine-readable output |

Behaviours reported: `AnywhereOnWebsite` (default), `Never`, `Unknown` (setting unreadable --
shown rather than assumed fine). Exit 2 if zero items were scanned, since that means
"saw nothing", not "nothing matches".

Matching is on the hostname: `example.com` and `*.example.com` match; `notexample.com` does not.

## Develop

```
.venv/bin/pip install -r requirements-dev.txt && .venv/bin/python -m pytest
```
