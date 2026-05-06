"""
Feature Extraction Module  (v2 — domain-agnostic)

Key improvement over v1:
  Features are computed on the PATH + QUERY portion of the URL only,
  NOT on the full URL including scheme://host:port.  This makes the
  classifier invariant to the server domain and eliminates false
  positives caused by unseen hostnames.

Extracts a 30-dimensional numerical feature vector.
"""

import re
import math
import urllib.parse
import numpy as np


# Keywords associated with known attack patterns
SQLI_KEYWORDS = [
    "select", "union", "insert", "update", "delete", "drop",
    "or 1=1", "' or", "-- ", "/*", "*/", "xp_", "exec", "cast(",
    "information_schema", "@@version", "sleep(", "benchmark(",
    "having", "group by", "order by",
]

XSS_KEYWORDS = [
    "<script", "javascript:", "onerror", "onload", "alert(",
    "document.cookie", "eval(", "<img", "<svg", "onmouseover",
    "onfocus", "onclick", "onmouseout", "<iframe", "<body",
    "fromcharcode", "innerhtml", "<input", "autofocus",
]

CMD_KEYWORDS = [
    "; ", " ;", "&&", "||", "| ", " |", "`", "$(", "wget ", "curl ",
    "/etc/passwd", "cat ", "ls ", "whoami", "nc ", "ping ",
    "/bin/sh", "/bin/bash", "python ", "perl ", "chmod ",
    "chown ", "rm ", "nmap ", "netcat",
]

TRAVERSAL_KEYS = [
    "../", "..\\", "%2e%2e", "....//", "/etc/", "c:\\windows",
    "/proc/", "/var/", "win.ini", "%252e", "..%2f", "..%5c",
]


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _count_special_chars(s: str) -> int:
    """Count security-relevant special characters."""
    return len(re.findall(r"['\";<>\(\)\{\}\[\]\\|&`$%]", s))


def _extract_path_query(url: str) -> str:
    """
    Extract just the path + query from a URL, stripping scheme://host:port.
    This is the KEY fix for domain-agnostic detection.

    Examples:
        "https://shop.example.com:443/products?id=1"  →  "/products?id=1"
        "http://example.com/search?q=hello"            →  "/search?q=hello"
        "/page?x=1"                                    →  "/page?x=1"
    """
    try:
        parsed = urllib.parse.urlparse(url)
        path = parsed.path or "/"
        if parsed.query:
            return path + "?" + parsed.query
        return path
    except Exception:
        return url


def extract_features(raw_request: dict) -> np.ndarray:
    """
    Extract a fixed-length feature vector from a parsed HTTP request.

    Parameters
    ----------
    raw_request : dict with keys:
        - url      : str  full URL
        - params   : str  query string or POST body
        - headers  : str  header block as single string
        - method   : str  GET/POST/etc.

    Returns
    -------
    np.ndarray  shape (30,) of float32 features
    """
    url     = urllib.parse.unquote_plus(raw_request.get("url", ""))
    params  = urllib.parse.unquote_plus(raw_request.get("params", ""))
    headers = raw_request.get("headers", "")
    method  = raw_request.get("method", "GET").upper()

    # ── Domain-agnostic: use path+query only ───────────────────────────
    path_query = _extract_path_query(url)

    # ── Build full text for keyword matching (lowercase) ───────────────
    full_text = (path_query + " " + params + " " + headers).lower()

    # ── Character counts used in multiple features ─────────────────────
    n_special_pq = _count_special_chars(path_query)
    n_special_p  = _count_special_chars(params)
    total_len    = max(len(full_text), 1)

    # ── Keyword counts ─────────────────────────────────────────────────
    sqli_hits      = sum(1 for kw in SQLI_KEYWORDS if kw in full_text)
    xss_hits       = sum(1 for kw in XSS_KEYWORDS if kw in full_text)
    cmd_hits       = sum(1 for kw in CMD_KEYWORDS if kw in full_text)
    traversal_hits = sum(1 for kw in TRAVERSAL_KEYS if kw in full_text)

    features = [
        # ── Length features (domain-agnostic) ──────────────────────  [0-2]
        len(path_query),           # path+query length only
        len(params),               # parameter length
        len(full_text),            # combined text length

        # ── Entropy features (domain-agnostic) ────────────────────  [3-4]
        _shannon_entropy(path_query),   # entropy of path+query
        _shannon_entropy(params),       # entropy of params

        # ── Special character counts ──────────────────────────────  [5-11]
        n_special_pq,              # special chars in path+query
        n_special_p,               # special chars in params
        full_text.count("'"),      # single quotes
        full_text.count('"'),      # double quotes
        full_text.count("--"),     # SQL comment sequences
        full_text.count("="),      # equals signs
        full_text.count("%"),      # percent signs

        # ── Attack keyword counts ─────────────────────────────────  [12-15]
        sqli_hits,                 # SQLi keyword matches
        xss_hits,                  # XSS keyword matches
        cmd_hits,                  # CMDi keyword matches
        traversal_hits,            # traversal pattern matches

        # ── URL-encoded attack characters ─────────────────────────  [16-19]
        full_text.count("%27"),    # encoded '
        full_text.count("%3c"),    # encoded <
        full_text.count("%3e"),    # encoded >
        full_text.count("%0a"),    # encoded newline

        # ── Structure signals ─────────────────────────────────────  [20-23]
        int(method == "POST"),
        path_query.count("/"),     # slashes in path only
        path_query.count("?"),
        path_query.count("&"),

        # ── Ratio features (normalised — key for generalisation) ──  [24-27]
        n_special_pq / max(len(path_query), 1),   # special char density
        n_special_p / max(len(params), 1),         # param special density
        (sqli_hits + xss_hits + cmd_hits + traversal_hits) / total_len * 100,  # keyword density
        max(len(v) for v in params.split("&") if v) if params else 0,  # longest param value

        # ── Suspicious path flag ──────────────────────────────────  [28]
        int(any(p in path_query.lower() for p in
                ["/admin", "/config", "/etc", "/proc", "/../",
                 "/exec", "/shell", "/cmd", "wp-admin", "phpmyadmin"])),

        # ── HTML/script tag present ───────────────────────────────  [29]
        int(bool(re.search(r"<\s*(script|img|svg|iframe|body|input|div|a)\b",
                           full_text, re.IGNORECASE))),
    ]

    return np.array(features, dtype=np.float32)


def batch_extract(records: list) -> np.ndarray:
    """Extract features from a list of request dicts."""
    return np.vstack([extract_features(r) for r in records])
