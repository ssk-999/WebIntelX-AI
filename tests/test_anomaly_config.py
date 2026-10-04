import yaml

from app.ml.config import DEFAULTS, load_config, validate


def test_shipped_yaml_matches_defaults_and_is_valid():
    cfg = load_config("config/anomaly.yaml")
    assert cfg.status == "ok" and cfg.error is None
    assert cfg.data == DEFAULTS                       # YAML and in-code defaults must not drift apart
    assert validate(cfg.data) == []


def test_partial_override_merges_with_defaults(tmp_path):
    f = tmp_path / "a.yaml"
    f.write_text(yaml.safe_dump({"score_threshold": 0.7, "model": {"random_state": 1}}))
    cfg = load_config(str(f))
    assert cfg.status == "ok" and cfg["score_threshold"] == 0.7
    assert cfg.model["random_state"] == 1 and cfg.model["n_estimators"] == 200 and cfg["min_deviation_z"] == 8.0


def test_missing_file_falls_back_visibly():
    cfg = load_config("does/not/exist.yaml")
    assert cfg.status == "fallback_defaults" and "not found" in cfg.error and cfg["score_threshold"] == 0.65


def test_invalid_values_fall_back_and_report(tmp_path):
    bad_cases = ({"score_threshold": 1.5}, {"score_threshold": 0}, {"min_deviation_z": -1}, {"min_training_sessions": "many"},
                 {"enabled": "yes"}, {"model": {"n_estimators": 0}}, {"model": {"random_state": 1.5}},
                 {"confidence": {"min": 0.9, "max": 0.5}}, {"confidence": {"min": -1}}, {"window_hours": True})
    for bad in bad_cases:
        f = tmp_path / "bad.yaml"
        f.write_text(yaml.safe_dump(bad))
        cfg = load_config(str(f))
        assert cfg.status == "fallback_defaults" and cfg.error, bad
        assert cfg["score_threshold"] == 0.65, bad     # defaults, not the bad value


def test_unparseable_yaml_and_non_mapping(tmp_path):
    f = tmp_path / "x.yaml"
    f.write_text("a: [unclosed")
    assert load_config(str(f)).status == "fallback_defaults"
    f.write_text("- just\n- a list\n")
    cfg = load_config(str(f))
    assert cfg.status == "fallback_defaults" and "mapping" in cfg.error


def test_public_view_has_no_secrets_and_is_a_copy():
    cfg = load_config("config/anomaly.yaml")
    pub = cfg.public()
    assert pub["status"] == "ok" and pub["score_threshold"] == 0.65
    pub["model"]["random_state"] = 999
    assert cfg.model["random_state"] == 42             # mutating the public view cannot change the live config
