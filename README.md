# op-autofill-audit

Find 1Password items on a domain (and its subdomains) whose website autofill is **not** set to
*"Only fill on this exact domain"*.

1Password's default autofill behaviour for a website is **fill anywhere on the site, including
subdomains**. For a domain where each subdomain is a different service (`grafana.example.com`,
`router.example.com`, `jellyfin.example.com`...) that means every login there is offered on every
other, and a compromised or look-alike subdomain gets a credential it should never have seen.
This tool lists the items still on that default, so you can tighten them.

## Why not just use the `op` CLI?

The CLI cannot read this setting. `op item get --format json` returns each URL as only
`label`, `primary` and `href`, and `op item create/edit` has no autofill option
([open request](https://www.1password.community/developers-69/feature-request-manage-autofill-behavior-via-cli-api-24225)).
The [1Password SDK](https://developer.1password.com/docs/sdks/) does expose it: each website on an
item carries an `autofill_behavior`, and listing items returns those websites directly, so the
whole audit is one list call per vault rather than one request per item.

## What it reports

For every website whose hostname is the domain or a subdomain of it:

| Behaviour | Meaning | Reported? |
|---|---|---|
| `AnywhereOnWebsite` | the default: fill on any page of the site, subdomains included | **yes** |
| `Never` | autofill disabled for that website | **yes** (so you can confirm it is deliberate) |
| `Unknown` | the setting could not be read; shown rather than assumed fine | **yes** |
| `UnparseableURL` | the stored URL is malformed, so its host is unknown; shown, never skipped | **yes** |
| `ExactDomain` | fill only when hostname **and port** match exactly (`www.` counts as different) | only with `--all` |

`Never` is listed because it is "not exact-domain", not because it is wrong: it is the right setting
for, say, several per-person logins on one hostname where autofill would only offer the wrong
account. Read that group and decide.

Matching is on the parsed hostname (a trailing DNS dot is ignored; a stored URL that can't be
parsed is reported as `UnparseableURL` rather than skipped): `example.com` and `*.example.com` match, `notexample.com` and
`example.com.evil.io` do not. URLs saved without a scheme or with a port are handled.

## Safety

- **Read-only.** It lists items and reads their website entries. It never requests a field value
  (password, OTP, note), and nothing is written to 1Password.
- **Local.** The audit reads item metadata through your desktop 1Password app (the SDK
  integration) and prints results to stdout. On first run the bootstrap downloads the
  dependencies into `.venv`, and the interactive setup can create or update `.env`. Nothing else
  is written to disk and nothing is sent anywhere else.
- **Output names real items.** Don't paste it somewhere public. `.gitignore` blocks `.env`,
  `*.json`, `*.csv`, `*.tsv` and `*.1pux` so a saved audit can't be committed by accident.
- It exits **2** if it scanned zero items: that means "saw nothing" (wrong account, integration
  off), which is not the same as "nothing needs fixing".

## Setup

1. In the 1Password desktop app: **Settings > Developer > "Integrate with the 1Password SDKs"**.
   Desktop-app auth is the only SDK auth that can see personal vaults (service accounts cannot),
   and access lapses after 10 minutes idle.
2. Run `./audit.py`. The first run:
   - creates `.venv` and installs `requirements.txt` into it, then restarts itself inside it
     (you only need a system Python 3.10+; every run re-checks `requirements.txt`, so an
     out-of-range SDK is repaired; if setup fails it prints the manual commands);
   - if the account or domain isn't configured and you're at a terminal, asks for them (prompts go
     to stderr, so `--json > file` stays valid) and writes a `.env` (mode 600, gitignored) using
     `.env.example` as the template.

`./audit.py --setup` re-runs the prompts later; Enter keeps the current values. Your account name or
sign-in address is shown by `op account list`.

## Use

```
./audit.py                                    # account and domain from .env
./audit.py --domain example.com --account my.1password.com
./audit.py --all --json > /somewhere/private.json
```

| flag | effect |
|---|---|
| `--domain` | domain to audit, subdomains included (`OP_AUDIT_DOMAIN`) |
| `--account` | account name or sign-in address (`OP_ACCOUNT_NAME`) |
| `--setup` | write `.env` interactively and exit |
| `--all` | also show websites already set to exact-domain |
| `--json` | machine-readable output |

Configuration precedence: **flag > real environment variable > `.env`**; blank values count as
unset. `--domain` must be a bare domain (`example.com`, `*.example.com` is accepted); URLs, ports
and paths are rejected rather than silently matching nothing.

Text output is tab-separated, `vault  title  behaviour  url`, with a summary on stderr:

```
Personal	Grafana	AnywhereOnWebsite	https://grafana.example.com
1 of 12 items on *.example.com reported; 598 items scanned
```

## Fixing what it finds

By hand, in the app: open the item, edit the website, **Autofill behavior**, then
**Only fill on this exact domain**. The SDK can also write this setting, but this tool deliberately
doesn't: updating an item replaces it as a whole, and a bug there would be touching real
credentials. If you need bulk changes, script them against a throwaway item first.

## Limitations

- Only items the SDK lists: active items in vaults your account can see (archived and trashed items
  are not included).
- This audits the *stored* website settings, not effective behaviour in every client: 1Password
  documents that the built-in Apple AutoFill suggestions on macOS, iOS and iPadOS don't reflect
  per-host restrictions ([details](https://support.1password.com/autofill-behavior/)).
- Only the per-website autofill setting. It doesn't look at URLs inside custom fields or notes.
- The SDK integration needs the desktop app running and unlocked.

## Develop

```
./audit.py --help > /dev/null                 # creates .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest
```

The tests need no 1Password, network or real SDK: `main()` runs with `collect()` stubbed, and
`collect()` itself runs against a fake `onepassword` module (vault traversal, item counting, the
no-vaults error). They cover the rules that matter -- hostname matching and look-alike domains,
what counts as "not exact" (including unreadable and malformed entries), domain validation,
`.env` and interactive setup, config precedence, and that zero scanned items is never a clean
result. The venv bootstrap is exercised for real in CI (`./audit.py --help`) rather than with a
faked `subprocess`. CI runs on pushes to `main` and on every pull request, on Python 3.10 and 3.12,
plus an import smoke test of the SDK. Prove a change to a guard by breaking it once and watching a
test fail.

## Licence

MIT.
