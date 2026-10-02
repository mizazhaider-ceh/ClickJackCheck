"""Tests for clickjackcheck.py. HTTP is fully mocked so no network is needed."""
import sys
import os
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests  # noqa: E402
import clickjackcheck  # noqa: E402


class FakeResponse:
    def __init__(self, status_code=200, headers=None):
        self.status_code = status_code
        self.headers = headers or {}


def fake_get_factory(resp_headers=None, status_code=200, exc=None):
    def _fake_get(url, timeout=10, headers=None, **kwargs):
        if exc:
            raise exc
        return FakeResponse(status_code=status_code, headers=resp_headers)

    return _fake_get


@pytest.fixture
def protected(monkeypatch):
    monkeypatch.setattr(
        requests, "get", fake_get_factory(resp_headers={"X-Frame-Options": "DENY"})
    )


@pytest.fixture
def unprotected(monkeypatch):
    monkeypatch.setattr(requests, "get", fake_get_factory(resp_headers={}))


@pytest.fixture
def csp_protected(monkeypatch):
    monkeypatch.setattr(
        requests,
        "get",
        fake_get_factory(
            resp_headers={
                "Content-Security-Policy": "default-src 'self'; frame-ancestors 'self'"
            }
        ),
    )


def test_normalize_url_adds_scheme():
    auditor = clickjackcheck.ClickJackAuditor("example.com")
    assert auditor.url == "https://example.com"


def test_normalize_url_keeps_scheme():
    auditor = clickjackcheck.ClickJackAuditor("http://example.com")
    assert auditor.url == "http://example.com"


def test_xfo_deny_is_protected(protected):
    auditor = clickjackcheck.ClickJackAuditor("example.com")
    res = auditor.check_protection()
    assert res["vulnerable"] is False
    assert res["protection_level"] == "good"
    assert res["x_frame_options"]["valid"] is True


def test_missing_headers_is_vulnerable(unprotected):
    auditor = clickjackcheck.ClickJackAuditor("example.com")
    res = auditor.check_protection()
    assert res["vulnerable"] is True
    assert res["protection_level"] == "none"
    assert len(res["recommendations"]) == 3


def test_csp_frame_ancestors_is_protected(csp_protected):
    auditor = clickjackcheck.ClickJackAuditor("example.com")
    res = auditor.check_protection()
    assert res["vulnerable"] is False
    assert res["protection_level"] == "good"
    assert res["protection_type"] == "Content-Security-Policy"


def test_allow_from_is_weak_not_good(monkeypatch):
    monkeypatch.setattr(
        requests,
        "get",
        fake_get_factory(resp_headers={"X-Frame-Options": "ALLOW-FROM https://example.com"}),
    )
    auditor = clickjackcheck.ClickJackAuditor("example.com")
    res = auditor.check_protection()
    assert res["protection_level"] == "weak"
    assert "Obsolete" in res["protection_value"]


def test_invalid_xfo_value_is_weak(monkeypatch):
    monkeypatch.setattr(
        requests, "get", fake_get_factory(resp_headers={"X-Frame-Options": "SOMETHING"})
    )
    auditor = clickjackcheck.ClickJackAuditor("example.com")
    res = auditor.check_protection()
    assert res["protection_level"] == "weak"
    assert "Invalid value" in res["protection_value"]


def test_request_failure(monkeypatch):
    monkeypatch.setattr(
        requests,
        "get",
        fake_get_factory(exc=requests.exceptions.ConnectionError("no route")),
    )
    auditor = clickjackcheck.ClickJackAuditor("example.com")
    res = auditor.check_protection()
    assert "error" in res
    assert res["protection_level"] == "error"


def test_json_output_has_no_markup(protected, capsys):
    rc = clickjackcheck.main(["example.com", "--json"])
    assert rc == 0
    out = capsys.readouterr().out
    import json as jsonlib

    data = jsonlib.loads(out)
    assert data["vulnerable"] is False
    assert "[" not in "".join(data["recommendations"])


def test_batch_file(monkeypatch, tmp_path, unprotected, capsys):
    target_file = tmp_path / "targets.txt"
    target_file.write_text("example.com\n# comment\n\nexample.org\n")
    rc = clickjackcheck.main(["--file", str(target_file), "--json"])
    assert rc == 0
    out = capsys.readouterr().out
    import json as jsonlib

    data = jsonlib.loads(out)
    assert isinstance(data, list)
    assert len(data) == 2
    assert all(d["vulnerable"] for d in data)


def test_missing_args_returns_error(capsys):
    rc = clickjackcheck.main([])
    assert rc == 2


def test_strip_rich_markup():
    assert clickjackcheck.strip_rich_markup("[bold]Add[/bold] X-Frame-Options") == "Add X-Frame-Options"
