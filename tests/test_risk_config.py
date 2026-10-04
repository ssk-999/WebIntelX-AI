"""Risk configuration: defaults == shipped YAML, validation, safe fallback (PRD sections 17, 33, 35)."""
import copy

import yaml

from app.risk.config import DEFAULTS, defaults, load_config, validate


def test_shipped_yaml_equals_builtin_defaults():
    cfg = load_config("config/risk.yaml")
    assert cfg.status == "ok" and cfg.data == DEFAULTS and validate(cfg.data) == []


def test_missing_file_falls_back(tmp_path):
    cfg = load_config(str(tmp_path / "nope.yaml"))
    assert cfg.status == "fallback_defaults" and cfg.data == DEFAULTS


def _write(tmp_path, data):
    p = tmp_path / "risk.yaml"
    p.write_text(yaml.safe_dump(data) if not isinstance(data, str) else data)
    return str(p)


def test_partial_override_merges_key_by_key(tmp_path):
    cfg = load_config(_write(tmp_path, {"weights": {"authentication": 40}, "levels": {"high": 60}}))
    assert cfg.status == "ok"
    assert cfg["weights"]["authentication"] == 40 and cfg["weights"]["behavior"] == DEFAULTS["weights"]["behavior"]
    assert cfg["levels"]["high"] == 60 and cfg["levels"]["critical"] == 85


def test_invalid_values_fall_back_with_reason(tmp_path):
    for bad in ({"weights": {"authentication": -1}}, {"weights": {"nonsense": 1}}, {"levels": {"medium": 90}},
                {"sensitive_endpoint": {"accessed": 1.5}}, {"asset_impact": {"path_prefixes": {"admin": 1.0}}},
                {"weights": {k: 0 for k in DEFAULTS["weights"]}}, {"enabled": "yes"},
                {"confidence": {"weights": {"signal_diversity": 0, "finding_confidence": 0, "correlation_strength": 0}}}):
        cfg = load_config(_write(tmp_path, bad))
        assert cfg.status == "fallback_defaults" and cfg.error, bad
        assert cfg.data == DEFAULTS


def test_garbage_yaml_falls_back(tmp_path):
    for text in ("weights: [unclosed\n  levels: {", "- a\n- b\n"):
        assert load_config(_write(tmp_path, text)).status == "fallback_defaults"


def test_fingerprint_changes_with_weights_only(tmp_path):
    a = defaults()
    b = load_config(_write(tmp_path, {"weights": {"authentication": 21}}))
    assert a.fingerprint != b.fingerprint and a.fingerprint == defaults().fingerprint
    assert "fingerprint" in a.public() and a.public()["status"] == "ok"
    assert copy.deepcopy(a.data) == DEFAULTS      # public() must not mutate the defaults
