"""Attack-indicator patterns (PRD section 14 Attack Agent input, section 25 additional scenarios).

These match characteristics of the request TARGET (path + query) only, after URL-decoding. Matching a
pattern is an INDICATOR, never proof of an attack attempt or compromise (PRD section 25 evidence
discipline). Request bodies and headers are not available to the platform and are not inspected.
"""
from __future__ import annotations

import re
from urllib.parse import unquote_plus

FLAGS = re.IGNORECASE

# (signal_name, regex). Order is irrelevant; all matching signal names are reported as evidence.
SQLI = [
    ("union_select", re.compile(r"\bunion\b(\s+all)?\s+select\b", FLAGS)),
    ("boolean_tautology", re.compile(r"\b(or|and)\s+(['\"]?)(\w+)\2\s*=\s*\2\3", FLAGS)),   # or 1=1 / or '1'='1
    ("stacked_statement", re.compile(r";\s*(drop|delete|insert|update|alter|truncate)\b", FLAGS)),
    ("drop_table", re.compile(r"\bdrop\s+table\b", FLAGS)),
    ("time_delay_function", re.compile(r"\b(sleep|pg_sleep|benchmark)\s*\(|waitfor\s+delay\b", FLAGS)),
    ("information_schema", re.compile(r"\binformation_schema\b", FLAGS)),
    ("quote_then_comment", re.compile(r"['\"]\s*--")),
]
XSS = [
    ("script_tag", re.compile(r"<\s*script\b", FLAGS)),
    ("javascript_uri", re.compile(r"\bjavascript\s*:", FLAGS)),
    ("event_handler_attr", re.compile(r"\bon(error|load|click|mouseover|mouseenter|focus)\s*=", FLAGS)),
    ("embedding_tag", re.compile(r"<\s*(iframe|svg|object|embed)\b", FLAGS)),
]
PATH_TRAVERSAL = [
    ("dot_dot_slash", re.compile(r"\.\.[/\\]")),
    ("sensitive_system_file", re.compile(r"(/etc/(passwd|shadow)\b|\bwin\.ini\b|\bboot\.ini\b)", FLAGS)),
]
_INTERNAL_HOST = (
    r"(localhost|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|0\.0\.0\.0|169\.254\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|\[?::1\]?|metadata\.google\.internal)"
)
SSRF = [  # applied to the QUERY string only
    ("internal_address_url", re.compile(r"\b(https?|ftp|gopher)://" + _INTERNAL_HOST, FLAGS)),
    ("file_scheme", re.compile(r"\bfile://", FLAGS)),
]

CATEGORIES = {
    # rule_id: (category, patterns, applies_to)
    "R-ATK-001": ("sql_injection_indicator", SQLI, "target"),
    "R-ATK-002": ("xss_indicator", XSS, "target"),
    "R-ATK-003": ("path_traversal_indicator", PATH_TRAVERSAL, "target"),
    "R-ATK-004": ("ssrf_indicator", SSRF, "query"),
}


def decode_target(endpoint: str, rounds: int = 2) -> str:
    """URL-decode up to `rounds` times (catches double-encoding) and drop NUL bytes."""
    s = endpoint or ""
    for _ in range(rounds):
        n = unquote_plus(s)
        if n == s:
            break
        s = n
    return s.replace("\x00", "")


def match_signals(patterns, text: str) -> list[str]:
    return [name for name, rx in patterns if rx.search(text)]
