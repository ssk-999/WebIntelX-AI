import yaml

from app.detection.config import DEFAULTS, load_config, validate


def test_shipped_yaml_matches_defaults_and_is_valid():
    cfg = load_config("config/detection.yaml")
    assert cfg.status == "ok" and cfg.error is None
    assert cfg.data["rules"] == DEFAULTS["rules"]            # YAML and in-code defaults must not drift apart
    assert validate(cfg.data) == []


def test_partial_override_merges_with_defaults(tmp_path):
    f = tmp_path / "d.yaml"
    f.write_text(yaml.safe_dump({"rules": {"R-AUTH-001": {"min_failures": 3}}}))
    cfg = load_config(str(f))
    assert cfg.status == "ok" and cfg.rule("R-AUTH-001")["min_failures"] == 3
    assert cfg.rule("R-AUTH-001")["run_gap_s"] == 30 and cfg.rule("R-BEH-001")["min_requests"] == 30


def test_missing_file_falls_back_visibly():
    cfg = load_config("does/not/exist.yaml")
    assert cfg.status == "fallback_defaults" and "not found" in cfg.error and cfg.rule("R-AUTH-001")["min_failures"] == 10


def test_invalid_values_fall_back_and_report(tmp_path):
    for bad in ({"rules": {"R-AUTH-001": {"min_failures": -1}}},
                {"rules": {"R-AUTH-001": {"confidence_base": 1.5}}},
                {"rules": {"R-AUTH-001": {"min_failures": "ten"}}},
                {"rules": {"R-AUTH-001": {"enabled": "yes"}}},
                {"analysis_window_hours": 0}, {"sensitive_path_prefixes": "oops"}):
        f = tmp_path / "bad.yaml"
        f.write_text(yaml.safe_dump(bad))
        cfg = load_config(str(f))
        assert cfg.status == "fallback_defaults" and cfg.error, bad
        assert cfg.rule("R-AUTH-001")["min_failures"] == 10          # defaults, not the bad value


def test_unparseable_yaml_and_non_mapping(tmp_path):
    f = tmp_path / "x.yaml"
    f.write_text("rules: [unclosed")
    assert load_config(str(f)).status == "fallback_defaults"
    f.write_text("- just\n- a list\n")
    assert load_config(str(f)).status == "fallback_defaults"
