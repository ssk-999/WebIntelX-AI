from app.threat_intel import config as tc


def test_defaults_are_valid_and_conservative():
    d = tc.defaults()
    assert d.status == "ok" and tc.validate(d.data) == []
    ind = d["indicators"]
    assert ind["domains"]["enabled"] is False and ind["ips"]["query_non_public"] is False


def test_repo_yaml_loads_ok():
    assert tc.load_config("config/threat_intel.yaml").status == "ok"


def test_missing_file_falls_back(tmp_path):
    c = tc.load_config(str(tmp_path / "nope.yaml"))
    assert c.status == "fallback_defaults" and c.error and c["enabled"] is True


def test_invalid_values_fall_back_and_are_reported(tmp_path):
    p = tmp_path / "ti.yaml"
    p.write_text("deadline_s: -1\nindicators: {max_per_incident: 0}\n")
    c = tc.load_config(str(p))
    assert c.status == "fallback_defaults" and "deadline_s" in c.error and c["deadline_s"] == 30


def test_unparseable_yaml_falls_back(tmp_path):
    p = tmp_path / "ti.yaml"
    p.write_text("a: [unclosed")
    assert tc.load_config(str(p)).status == "fallback_defaults"


def test_partial_file_overrides_key_by_key(tmp_path):
    p = tmp_path / "ti.yaml"
    p.write_text("indicators:\n  domains: {enabled: true}\ncache_ttl_s: 0\n")
    c = tc.load_config(str(p))
    assert c.status == "ok" and c["indicators"]["domains"]["enabled"] is True and c["indicators"]["cves"]["enabled"] is True and c["cache_ttl_s"] == 0


def test_public_has_no_secrets():
    assert "key" not in " ".join(tc.defaults().public()).lower().replace("without_key", "").replace("with_key", "")
