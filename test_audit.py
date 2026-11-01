from types import SimpleNamespace as NS

import audit


def site(url, behaviour):
    return NS(url=url, autofill_behavior=NS(value=behaviour) if behaviour else None)


def test_domain_and_subdomain_match():
    assert audit.on_domain("example.com", "example.com")
    assert audit.on_domain("a.b.example.com", "example.com")


def test_lookalike_domains_do_not_match():
    assert not audit.on_domain("notexample.com", "example.com")
    assert not audit.on_domain("example.com.evil.io", "example.com")


def test_host_of_tolerates_missing_scheme_and_port():
    assert audit.host_of("Sub.Example.com:8006/x") == "sub.example.com"
    assert audit.host_of("https://example.com/ui") == "example.com"


def test_classify_keeps_only_matching_sites():
    sites = [site("https://a.example.com", "ExactDomain"), site("https://other.org", "Never")]
    assert audit.classify(sites, "example.com") == [
        {"url": "https://a.example.com", "behaviour": "ExactDomain"}
    ]


def test_not_exact_flags_default_never_and_unknown():
    got = audit.classify(
        [
            site("https://a.example.com", "AnywhereOnWebsite"),
            site("https://b.example.com", "Never"),
            site("https://c.example.com", None),
            site("https://d.example.com", "ExactDomain"),
        ],
        "example.com",
    )
    assert [s["behaviour"] for s in audit.not_exact(got)] == [
        "AnywhereOnWebsite",
        "Never",
        "Unknown",
    ]


def test_no_websites_is_empty():
    assert audit.classify(None, "example.com") == []


def test_load_env_parses_and_does_not_override(tmp_path):
    f = tmp_path / ".env"
    f.write_text('# c\n\nA=1\nexport B="two words"\nC=\'x\'\nKEEP=file\nnoequals\n')
    env = {"KEEP": "real"}
    audit.load_env(str(f), env)
    assert env == {"A": "1", "B": "two words", "C": "x", "KEEP": "real"}


def test_load_env_missing_file_is_noop(tmp_path):
    env = {}
    audit.load_env(str(tmp_path / "nope"), env)
    assert env == {}


TEMPLATE = "# header\n\n# the account\nA=ex1\n\n# the domain\n# second line\nB=ex2\n"


def test_parse_template_attaches_help_but_not_header():
    got = audit.parse_template(TEMPLATE)
    assert got == [
        audit.Entry("A", "ex1", "the account"),
        audit.Entry("B", "ex2", "the domain second line"),
    ]


def _run_setup(tmp_path, answers, existing=None):
    tpl = tmp_path / ".env.example"
    tpl.write_text(TEMPLATE)
    env = tmp_path / ".env"
    if existing:
        env.write_text(existing)
    it = iter(answers)
    audit.setup(str(tpl), str(env), ask=lambda _p: next(it), out=lambda *_: None)
    return env


def test_setup_writes_values_mode_600_and_roundtrips(tmp_path):
    env = _run_setup(tmp_path, ["acct", "two words"])
    assert oct(env.stat().st_mode & 0o777) == "0o600"
    assert audit.read_env_file(str(env)) == {"A": "acct", "B": "two words"}


def test_setup_reprompts_on_blank_and_never_accepts_the_example(tmp_path):
    env = _run_setup(tmp_path, ["", "", "real", "d.com"])
    assert audit.read_env_file(str(env)) == {"A": "real", "B": "d.com"}


def test_setup_enter_keeps_existing_values(tmp_path):
    env = _run_setup(tmp_path, ["", "new"], existing="A=keep\nB=old\n")
    assert audit.read_env_file(str(env)) == {"A": "keep", "B": "new"}


def test_setup_tightens_a_loose_existing_file(tmp_path):
    env = tmp_path / ".env"
    env.write_text("A=x\nB=y\n")
    env.chmod(0o644)
    _run_setup(tmp_path, ["", ""], existing="A=x\nB=y\n")
    assert oct(env.stat().st_mode & 0o777) == "0o600"
