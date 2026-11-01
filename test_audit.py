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
