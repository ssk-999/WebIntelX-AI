from app.pipeline import masking as m


def test_secret_keys_redacted_recursively():
    out = m.mask_value({"password": "hunter2", "ok": "x", "nested": {"api_key": "abc", "Authorization": "Bearer abcdefgh12345"}})
    assert out["password"] == m.REDACTED
    assert out["nested"]["api_key"] == m.REDACTED
    assert out["nested"]["Authorization"] == m.REDACTED
    assert out["ok"] == "x"


def test_text_masking():
    t = m.mask_text("mail bob@corp.com token=abc123 card 4111 1111 1111 1111 Bearer abcdefghijkl")
    assert "bob@corp.com" not in t and "abc123" not in t and "4111" not in t and "abcdefghijkl" not in t


def test_endpoint_masking_keeps_path():
    out = m.mask_endpoint("/api/login?user=bob&password=hunter2&page=2")
    assert out.startswith("/api/login?")
    assert "hunter2" not in out and "page=2" in out


def test_ip_modes():
    assert m.privacy_safe_ip("203.0.113.77", "none", "s") == "203.0.113.77"
    assert m.privacy_safe_ip("203.0.113.77", "truncate", "s") == "203.0.113.0/24"
    h1 = m.privacy_safe_ip("203.0.113.77", "hash", "s")
    assert h1 == m.privacy_safe_ip("203.0.113.77", "hash", "s") and h1.startswith("iph_")
    assert h1 != m.privacy_safe_ip("203.0.113.77", "hash", "other")


def test_user_id_pseudonym_is_stable():
    a = m.pseudonymize_user_id("Alice@Example.com", "s")
    assert a == m.pseudonymize_user_id("alice@example.com", "s") and "@" not in a
    assert m.pseudonymize_user_id("visitor-42", "s") == "visitor-42"
