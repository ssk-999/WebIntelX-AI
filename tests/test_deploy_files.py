"""M10 Part 2: static checks of the deployment files (PRD FR-25 / section 35: no secrets in source, secrets via environment or secrets
management). They read text files only; Docker itself is not needed. Plain asserts, no pytest import."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_SECRET_ASSIGN = re.compile(r"(GROQ_API_KEY|TI_API_KEY|NVD_API_KEY|PRIVACY_SALT)[ \t]*[=:][ \t]*[\"']?[A-Za-z0-9_\-]{12,}")


def _read(name):
    return (ROOT / name).read_text(encoding="utf-8")


def _has_secret(text):
    """True when a secret-looking value is assigned. The documented `change-me...` placeholder is not a secret."""
    return any("change-me" not in m.group(0) for m in _SECRET_ASSIGN.finditer(text))


def test_dockerfile_runs_as_non_root_with_healthcheck_and_no_baked_secrets():
    d = _read("Dockerfile")
    assert "USER appuser" in d and "HEALTHCHECK" in d and "EXPOSE 8000" in d and "uvicorn app.main:app" in d
    assert not _has_secret(d), "a secret value appears to be baked into the Dockerfile"
    assert "COPY .env" not in d and "sqlite:////data/" in d


def test_dockerignore_keeps_secrets_and_local_databases_out_of_the_image():
    i = _read(".dockerignore").split()
    assert {".env", "*.db", ".streamlit/secrets.toml"} <= set(i)


def test_gitignore_keeps_env_and_streamlit_secrets_out_of_git():
    g = _read(".gitignore").split()
    assert ".env" in g and ".streamlit/secrets.toml" in g


def test_compose_passes_secrets_only_by_substitution():
    c = _read("docker-compose.yml")
    assert not _has_secret(c) and "${GROQ_API_KEY:-}" in c and "WEBINTELX_API_URL: http://backend:8000" in c


def test_example_files_contain_no_real_secret_values():
    for name in (".env.example", ".streamlit/secrets.toml.example"):
        text = _read(name)
        assert not _has_secret(text), name
    assert 'GROQ_API_KEY = ""' in _read(".streamlit/secrets.toml.example")
    assert "WEBINTELX_EMBEDDED_BACKEND" in _read(".env.example")


def test_requirements_list_what_the_dashboard_and_backend_import():
    r = _read("requirements.txt").lower()
    for pkg in ("fastapi", "uvicorn", "streamlit", "plotly", "httpx", "sqlalchemy", "crewai"):
        assert pkg in r, pkg


if __name__ == "__main__":
    fails = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
            except Exception as exc:  # noqa: BLE001
                fails += 1
                print("FAIL", name, repr(exc))
    print("failures:", fails)
