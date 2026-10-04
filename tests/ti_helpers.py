"""Helpers for threat-intelligence tests. No real network: every provider call goes through httpx.MockTransport."""
import httpx


def mock_client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def otx_body(count=0, **extra):
    body = {"indicator": "x", "pulse_info": {"count": count, "pulses": [{"name": f"pulse {i}"} for i in range(count)]}, **extra}
    return body


NVD_CVE = {
    "resultsPerPage": 1, "totalResults": 1,
    "vulnerabilities": [{"cve": {
        "id": "CVE-2021-44228", "published": "2021-12-10T10:15:09.143", "lastModified": "2024-01-01T00:00:00.000", "vulnStatus": "Analyzed",
        "descriptions": [{"lang": "es", "value": "descripcion"}, {"lang": "en", "value": "Remote code execution via JNDI lookups.\x00 extra"}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"version": "3.1", "baseScore": 10.0, "baseSeverity": "CRITICAL"}}]},
        "weaknesses": [{"description": [{"lang": "en", "value": "CWE-502"}, {"lang": "en", "value": "NVD-CWE-Other"}]}],
    }}],
}
