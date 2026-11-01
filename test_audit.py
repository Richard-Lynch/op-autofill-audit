import json
import os
import subprocess
from types import SimpleNamespace as NS

import pytest

import audit


def site(url, behaviour):
    return NS(url=url, autofill_behavior=NS(value=behaviour) if behaviour else None)


# --- matching and classification ----------------------------------------------------


@pytest.mark.parametrize(
    "host, expected",
    [
        ("example.com", True),
        ("a.b.example.com", True),
        ("notexample.com", False),  # suffix match without the dot boundary
        ("example.com.evil.io", False),
        ("", False),
    ],
)
def test_on_domain(host, expected):
    assert audit.on_domain(host, "example.com") is expected


@pytest.mark.parametrize(
    "url, host",
    [
        ("https://example.com/ui", "example.com"),
        ("Sub.Example.com:8006/x", "sub.example.com"),  # no scheme, port, mixed case
        ("http://h.example.com:3000/login", "h.example.com"),
        ("//sub.example.com/login", "sub.example.com"),  # scheme-relative
        ("example.com/?next=https://other.org", "example.com"),  # "://" in the query
        ("example.com.", "example.com"),  # DNS root dot
        ("  https://example.com  ", "example.com"),
    ],
)
def test_host_of(url, host):
    assert audit.host_of(url) == host


@pytest.mark.parametrize(
    "raw, domain",
    [("example.com", "example.com"), (" *.Example.COM. ", "example.com")],
)
def test_normalize_domain(raw, domain):
    assert audit.normalize_domain(raw) == domain


@pytest.mark.parametrize("raw", ["https://example.com", "example.com:8006", "a.com/x", "*", "", "a b.com"])
def test_normalize_domain_rejects_what_would_silently_match_nothing(raw):
    with pytest.raises(ValueError):
        audit.normalize_domain(raw)


def test_malformed_url_is_reported_not_crashed_or_skipped():
    with pytest.raises(ValueError):
        audit.host_of("https://[bad")
    got = audit.classify([site("https://[bad", "ExactDomain")], "example.com")
    assert [s["behaviour"] for s in audit.not_exact(got)] == ["UnparseableURL"]


@pytest.mark.parametrize(
    "value, name",
    [(NS(value="Never"), "Never"), ("ExactDomain", "ExactDomain"), (None, "Unknown")],
)
def test_behaviour_name(value, name):
    assert audit.behaviour_name(value) == name


def test_classify_filters_domain_and_not_exact_keeps_everything_else():
    sites = [
        site("https://a.example.com", "AnywhereOnWebsite"),
        site("https://b.example.com", "Never"),
        site("https://c.example.com", None),  # unreadable must not read as fine
        site("https://d.example.com", "ExactDomain"),
        site("https://other.org", "Never"),  # wrong domain
    ]
    got = audit.classify(sites, "example.com")
    assert len(got) == 4
    assert [s["behaviour"] for s in audit.not_exact(got)] == ["AnywhereOnWebsite", "Never", "Unknown"]
    assert audit.classify(None, "example.com") == []


# --- .env parsing, template and interactive setup ------------------------------------


@pytest.mark.parametrize(
    "text, expected",
    [
        ('# c\n\nA=1\nexport B="two words"\nC=\'x\'\nnoequals\n', {"A": "1", "B": "two words", "C": "x"}),
        ("A=\n", {"A": ""}),
        ("", {}),
    ],
)
def test_read_env_file(tmp_path, text, expected):
    f = tmp_path / ".env"
    f.write_text(text)
    assert audit.read_env_file(str(f)) == expected


def test_read_env_missing_file(tmp_path):
    assert audit.read_env_file(str(tmp_path / "nope")) == {}


TEMPLATE = "# header\n\n# the account\nA=ex1\n\n# the domain\n# second line\nB=ex2\n"


def test_parse_template_attaches_help_but_not_the_header():
    assert audit.parse_template(TEMPLATE) == [
        audit.Entry("A", "ex1", "the account"),
        audit.Entry("B", "ex2", "the domain second line"),
    ]


@pytest.mark.parametrize(
    "answers, existing, expected",
    [
        (["acct", "two words"], "", {"A": "acct", "B": "two words"}),
        (["", "", "real", "d.com"], "", {"A": "real", "B": "d.com"}),  # blank re-prompts
        (["", "new"], "A=keep\nB=old\n", {"A": "keep", "B": "new"}),  # Enter keeps current
        (["", "x", "y"], "A=\nB=old\n", {"A": "x", "B": "y"}),  # a blank existing value is unset
    ],
)
def test_setup(tmp_path, answers, existing, expected):
    (tmp_path / ".env.example").write_text(TEMPLATE)
    env = tmp_path / ".env"
    if existing:
        env.write_text(existing)
        env.chmod(0o644)
    it = iter(answers)
    audit.setup(str(tmp_path / ".env.example"), str(env), ask=lambda *_: next(it), out=lambda *_: None)
    assert audit.read_env_file(str(env)) == expected
    assert env.stat().st_mode & 0o777 == 0o600  # also tightens a loose pre-existing file


# --- main(): config precedence, filtering, exit codes ---------------------------------

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
    monkeypatch.setattr(audit.sys, "stdin", NS(isatty=lambda: False))
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

    return NS(run=run, calls=calls, fake=fake_collect, env=tmp_path / ".env")


@pytest.mark.parametrize(
    "extra, titles",
    [([], ["Mixed"]), (["--all"], ["AllExact", "Mixed"])],
)
def test_main_json_filters_exact_unless_all(m, capsys, extra, titles):
    assert m.run("--account", "a", "--domain", "example.com", "--json", *extra) == 0
    assert sorted(r["title"] for r in json.loads(capsys.readouterr().out)) == titles


def test_main_text_output_is_tab_separated(m, capsys):
    m.run("--account", "a", "--domain", "example.com")
    assert capsys.readouterr().out.strip() == "V\tMixed\tAnywhereOnWebsite\thttps://b.example.com"


def test_main_zero_items_scanned_is_exit_2_not_clean(m, capsys):
    m.fake.result = ([], 0)
    assert m.run("--account", "a", "--domain", "example.com") == 2
    assert "not a clean result" in capsys.readouterr().err


@pytest.mark.parametrize(
    "argv, env_file, expected",
    [
        ([], "OP_ACCOUNT_NAME=f\nOP_AUDIT_DOMAIN=*.Example.COM\n", ("f", "example.com")),
        (["--domain", "flag.com"], "OP_ACCOUNT_NAME=f\nOP_AUDIT_DOMAIN=file.com\n", ("f", "flag.com")),
        (["--account", "a", "--domain", "d.com"], None, ("a", "d.com")),
        ([], "OP_ACCOUNT_NAME=\nOP_AUDIT_DOMAIN=d.com\n", None),  # blank = missing, no tty -> error
    ],
)
def test_main_config_precedence_and_domain_normalising(m, argv, env_file, expected):
    if expected is None:
        with pytest.raises(SystemExit):
            m.run(*argv, env_file=env_file)
        return
    m.run(*argv, env_file=env_file)
    assert m.calls == [expected]


@pytest.mark.parametrize("domain", ["https://example.com", "example.com:8006", "*"])
def test_main_rejects_an_invalid_domain_instead_of_reporting_clean(m, domain):
    with pytest.raises(SystemExit) as exc:
        m.run("--account", "a", "--domain", domain)
    assert exc.value.code == 2 and m.calls == []


def test_first_run_prompts_go_to_stderr_so_json_stays_parseable(m, capsys):
    assert m.run("--json", "--all", tty=True, answers=["me", "example.com"]) == 0
    cap = capsys.readouterr()
    assert len(json.loads(cap.out)) == 2 and "OP_ACCOUNT_NAME" in cap.err


def test_setup_replaces_stale_config_instead_of_auditing_the_old_account(m):
    m.run("--setup", tty=True, answers=["old", "example.com"])
    m.run(tty=True, env_file="OP_ACCOUNT_NAME=old\n", answers=["new", "example.com"])
    assert m.calls == [("new", "example.com")]


def test_main_missing_config_without_a_tty_errors_instead_of_prompting(m):
    with pytest.raises(SystemExit) as exc:
        m.run("--domain", "example.com")
    assert exc.value.code == 2 and m.calls == []


@pytest.mark.parametrize("argv, audits", [([], True), (["--setup"], False)])
def test_main_setup_paths(m, argv, audits):
    assert m.run(*argv, tty=True, answers=["me", "example.com"]) == 0
    assert m.calls == ([("me", "example.com")] if audits else [])
    assert audit.read_env_file(str(m.env)) == {"OP_ACCOUNT_NAME": "me", "OP_AUDIT_DOMAIN": "example.com"}


# --- bootstrap(): venv creation, install and re-exec ----------------------------------


@pytest.fixture
def boot(tmp_path, monkeypatch):
    venv = tmp_path / ".venv"
    py = venv / "bin" / "python"
    monkeypatch.setattr(audit, "VENV_DIR", str(venv))
    monkeypatch.setattr(audit, "_venv_python", lambda: str(py))
    monkeypatch.delenv(audit.BOOTSTRAPPED, raising=False)
    monkeypatch.setattr(audit.sys, "prefix", "/some/other/prefix")
    cmds, execs = [], []

    def fake_run(cmd, **kw):
        cmds.append(" ".join(cmd))
        if "venv" in cmd:
            py.parent.mkdir(parents=True)
            py.write_text("")
        # the `import onepassword` probe fails until pip has run
        installed = any("pip install" in c for c in cmds)
        return NS(returncode=0 if installed or "-c" not in cmd else 1)

    monkeypatch.setattr(audit.subprocess, "run", fake_run)
    monkeypatch.setattr(audit.os, "execv", lambda p, argv: execs.append(p))
    return NS(cmds=cmds, execs=execs, py=py, venv=venv, mp=monkeypatch)


def test_bootstrap_first_run_creates_venv_installs_and_reexecs(boot):
    audit.bootstrap()
    assert any("-m venv" in c for c in boot.cmds)
    assert any("pip install" in c and "requirements.txt" in c for c in boot.cmds)
    assert boot.execs == [str(boot.py)] and os.environ[audit.BOOTSTRAPPED] == "1"
    boot.mp.delenv(audit.BOOTSTRAPPED)


@pytest.mark.parametrize("in_venv, guard", [(False, True), (True, False)])
def test_bootstrap_does_nothing_when_guarded_or_already_in_a_ready_venv(boot, in_venv, guard):
    if guard:
        boot.mp.setenv(audit.BOOTSTRAPPED, "1")
    if in_venv:
        boot.py.parent.mkdir(parents=True)
        boot.py.write_text("")
        boot.cmds.append("pip install")  # deps already present
        boot.mp.setattr(audit.sys, "prefix", str(boot.venv))
    n = len(boot.cmds)
    audit.bootstrap()
    assert boot.execs == [] and (guard is False or len(boot.cmds) == n)


def test_bootstrap_failure_names_the_manual_fix(boot):
    def boom(cmd, **kw):
        raise subprocess.CalledProcessError(1, cmd)

    boot.mp.setattr(audit.subprocess, "run", boom)
    with pytest.raises(SystemExit, match="pip install -r requirements.txt"):
        audit.bootstrap()
    assert boot.execs == []


def test_bootstrap_rejects_an_old_python_before_touching_anything(boot):
    boot.mp.setattr(audit.sys, "version_info", (3, 9, 0))
    with pytest.raises(SystemExit, match="3.10"):
        audit.bootstrap()
    assert boot.cmds == [] and boot.execs == []


def test_bootstrap_reconciles_requirements_even_when_the_sdk_imports(boot):
    boot.py.parent.mkdir(parents=True)
    boot.py.write_text("")
    boot.mp.setattr(audit.sys, "prefix", str(boot.venv))
    audit.bootstrap()
    assert any("pip install" in c for c in boot.cmds) and boot.execs == []
