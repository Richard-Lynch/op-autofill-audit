import asyncio
import json
import sys
from types import SimpleNamespace as NS

import pytest

import audit


def site(url, behaviour):
    return NS(url=url, autofill_behavior=NS(value=behaviour) if behaviour else None)


# --- matching, normalising, classifying -----------------------------------------------


@pytest.mark.parametrize(
    "host, expected",
    [("example.com", True), ("a.b.example.com", True), ("notexample.com", False)],
)
def test_on_domain(host, expected):
    assert audit.on_domain(host, "example.com") is expected


@pytest.mark.parametrize(
    "url, host",
    [
        ("Sub.Example.com:8006/x", "sub.example.com"),  # no scheme, port, mixed case
        ("//sub.example.com/login", "sub.example.com"),  # scheme-relative
        ("example.com/?next=https://other.org", "example.com"),  # "://" in the query
        ("example.com.", "example.com"),  # DNS root dot
    ],
)
def test_host_of(url, host):
    assert audit.host_of(url) == host


def test_normalize_domain():
    assert audit.normalize_domain(" *.Example.COM. ") == "example.com"


@pytest.mark.parametrize("raw", ["https://example.com", "example.com:8006", "a.com/x", "*", ""])
def test_normalize_domain_rejects_what_would_silently_match_nothing(raw):
    with pytest.raises(ValueError):
        audit.normalize_domain(raw)


def test_classify_reports_everything_that_is_not_known_exact():
    got = audit.classify(
        [
            site("https://a.example.com", "AnywhereOnWebsite"),
            site("https://b.example.com", "Never"),
            site("https://c.example.com", None),  # unreadable must not read as fine
            site("https://[bad", "ExactDomain"),  # unparseable: shown, never skipped or fatal
            site("https://d.example.com", "ExactDomain"),
            site("https://other.org", "Never"),  # a different domain
        ],
        "example.com",
    )
    assert len(got) == 5
    assert [s["behaviour"] for s in audit.not_exact(got)] == [
        "AnywhereOnWebsite",
        "Never",
        "Unknown",
        "UnparseableURL",
    ]


# --- .env and interactive setup -------------------------------------------------------


def test_read_env_file(tmp_path):
    f = tmp_path / ".env"
    f.write_text('# c\n\nA=1\nexport B="two words"\nC=\'x\'\nD=\nnoequals\n')
    assert audit.read_env_file(str(f)) == {"A": "1", "B": "two words", "C": "x", "D": ""}
    assert audit.read_env_file(str(tmp_path / "missing")) == {}


@pytest.mark.parametrize(
    "answers, existing, expected",
    [
        (["", "real", "d.com"], "", {"A": "real", "B": "d.com"}),  # blank re-prompts
        (["", "new"], "A=keep\nB=old\n", {"A": "keep", "B": "new"}),  # Enter keeps current
        (["x", "y"], "A=\nB=old\n", {"A": "x", "B": "y"}),  # a blank existing value is unset
    ],
)
def test_setup(tmp_path, answers, existing, expected):
    (tmp_path / ".env.example").write_text("# the account\nA=ex1\n\n# the domain\nB=ex2\n")
    env = tmp_path / ".env"
    if existing:
        env.write_text(existing)
        env.chmod(0o644)
    it = iter(answers)
    audit.setup(str(tmp_path / ".env.example"), str(env), ask=lambda _p: next(it), out=lambda *_: None)
    assert audit.read_env_file(str(env)) == expected
    assert env.stat().st_mode & 0o777 == 0o600  # also tightens a loose pre-existing file


# --- collect(): the SDK boundary, faked -----------------------------------------------


def fake_sdk(monkeypatch, vaults):
    """vaults: {title: [item, ...]}; installs a stand-in `onepassword` module."""

    async def authenticate(**_):
        async def list_vaults():
            return [NS(id=t, title=t) for t in vaults]

        async def list_items(vault_id):
            return vaults[vault_id]

        return NS(vaults=NS(list=list_vaults), items=NS(list=list_items))

    sdk = NS(Client=NS(authenticate=authenticate), DesktopAuth=lambda account_name: None)
    monkeypatch.setitem(sys.modules, "onepassword", sdk)


def test_collect_walks_every_vault_and_counts_every_item(monkeypatch):
    def item(title, *sites):
        return NS(id=title, title=title, websites=list(sites))

    fake_sdk(
        monkeypatch,
        {
            "V1": [item("hit", site("https://a.example.com", "Never")), item("miss", site("https://x.org", None))],
            "V2": [item("hit2", site("https://b.example.com", "ExactDomain")), item("bare")],
        },
    )
    rows, seen = asyncio.run(audit.collect("acct", "example.com"))
    assert (seen, [(r["vault"], r["title"]) for r in rows]) == (4, [("V1", "hit"), ("V2", "hit2")])


def test_collect_with_no_visible_vaults_is_an_error_not_a_clean_scan(monkeypatch):
    fake_sdk(monkeypatch, {})
    with pytest.raises(SystemExit, match="no vaults visible"):
        asyncio.run(audit.collect("acct", "example.com"))


# --- main(): output, exit codes, config -----------------------------------------------

ROWS = [
    {"vault": "V", "title": "Mixed", "id": "1", "sites": [
        {"url": "https://a.example.com", "behaviour": "ExactDomain"},
        {"url": "https://b.example.com", "behaviour": "AnywhereOnWebsite"},
    ]},
    {"vault": "V", "title": "AllExact", "id": "2", "sites": [
        {"url": "https://c.example.com", "behaviour": "ExactDomain"},
    ]},
]  # fmt: skip


@pytest.fixture
def m(tmp_path, monkeypatch):
    """main() with no real .env or config in the environment, and collect() stubbed."""
    monkeypatch.setattr(audit, "ENV_FILE", str(tmp_path / ".env"))
    monkeypatch.setattr(audit, "ENV_TEMPLATE", str(tmp_path / ".env.example"))
    (tmp_path / ".env.example").write_text("# a\nOP_ACCOUNT_NAME=x\n\n# d\nOP_AUDIT_DOMAIN=y\n")
    for k in ("OP_ACCOUNT_NAME", "OP_AUDIT_DOMAIN"):
        monkeypatch.delenv(k, raising=False)
    calls = []

    async def fake_collect(account, domain):
        calls.append((account, domain))
        return fake_collect.result

    fake_collect.result = (ROWS, 10)
    monkeypatch.setattr(audit, "collect", fake_collect)

    def run(*argv, env_file=None, tty=False, answers=()):
        if env_file is not None:
            (tmp_path / ".env").write_text(env_file)
        monkeypatch.setattr(audit.sys, "argv", ["audit.py", *argv])
        monkeypatch.setattr(audit.sys, "stdin", NS(isatty=lambda: tty))
        it = iter(answers)
        monkeypatch.setattr("builtins.input", lambda *_: next(it))
        return audit.main()

    return NS(run=run, calls=calls, fake=fake_collect, env=tmp_path / ".env", mp=monkeypatch)


@pytest.mark.parametrize("extra, titles", [([], ["Mixed"]), (["--all"], ["AllExact", "Mixed"])])
def test_main_json_filters_exact_unless_all(m, capsys, extra, titles):
    assert m.run("--account", "a", "--domain", "example.com", "--json", *extra) == 0
    out = json.loads(capsys.readouterr().out)
    assert sorted(r["title"] for r in out) == titles
    assert extra or [s["behaviour"] for s in out[0]["sites"]] == ["AnywhereOnWebsite"]


def test_main_text_output_is_tab_separated(m, capsys):
    m.run("--account", "a", "--domain", "example.com")
    assert capsys.readouterr().out.strip() == "V\tMixed\tAnywhereOnWebsite\thttps://b.example.com"


def test_main_zero_items_scanned_is_exit_2_not_clean(m, capsys):
    m.fake.result = ([], 0)
    assert m.run("--account", "a", "--domain", "example.com") == 2
    assert "not a clean result" in capsys.readouterr().err


@pytest.mark.parametrize(
    "argv, env, expected",
    [
        ([], {}, ("f", "file.com")),  # .env file
        (["--domain", "flag.com"], {}, ("f", "flag.com")),  # flag beats file
        ([], {"OP_AUDIT_DOMAIN": "env.com"}, ("f", "env.com")),  # environment beats file
    ],
)
def test_main_config_precedence(m, argv, env, expected):
    for k, v in env.items():
        m.mp.setenv(k, v)
    m.run(*argv, env_file="OP_ACCOUNT_NAME=f\nOP_AUDIT_DOMAIN=file.com\n")
    assert m.calls == [expected]


def test_main_rejects_an_invalid_domain_instead_of_reporting_clean(m):
    with pytest.raises(SystemExit) as exc:
        m.run("--account", "a", "--domain", "https://example.com")
    assert exc.value.code == 2 and m.calls == []


def test_main_missing_config_without_a_tty_errors_instead_of_prompting(m):
    with pytest.raises(SystemExit) as exc:
        m.run("--domain", "example.com")
    assert exc.value.code == 2 and m.calls == []


def test_first_run_prompts_go_to_stderr_so_json_stays_parseable(m, capsys):
    assert m.run("--json", "--all", tty=True, answers=["me", "example.com"]) == 0
    cap = capsys.readouterr()
    assert len(json.loads(cap.out)) == 2 and "OP_ACCOUNT_NAME" in cap.err


def test_setup_replaces_stale_config_instead_of_auditing_the_old_account(m):
    m.run(tty=True, env_file="OP_ACCOUNT_NAME=old\n", answers=["new", "example.com"])
    assert m.calls == [("new", "example.com")]


def test_main_setup_flag_writes_env_and_does_not_audit(m):
    assert m.run("--setup", tty=True, answers=["me", "example.com"]) == 0
    assert m.calls == []
    assert audit.read_env_file(str(m.env)) == {"OP_ACCOUNT_NAME": "me", "OP_AUDIT_DOMAIN": "example.com"}
