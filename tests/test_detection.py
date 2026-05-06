import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from utils.feature_extractor import extract_features
from models.classical_ml import AnomalyDetector, AttackClassifier

TEST_CASES = [
    {
        "name":     "Normal - Gifts",
        "expected": "normal",
        "request":  {
            "url":     "https://0a1234.web-security-academy.net:443/filter?category=Gifts",
            "params":  "category=Gifts",
            "headers": "Host: 0a1234.web-security-academy.net",
            "method":  "GET",
        },
    },
    {
        "name":     "Normal - Tech gifts",
        "expected": "normal",
        "request":  {
            "url":     "https://0a1234.web-security-academy.net:443/filter?category=Tech+gifts",
            "params":  "category=Tech+gifts",
            "headers": "Host: 0a1234.web-security-academy.net",
            "method":  "GET",
        },
    },
    {
        "name":     "SQL injection",
        "expected": "sqli",
        "request":  {
            "url":     "https://0a1234.web-security-academy.net:443/filter?category=Gifts'+OR+1=1--",
            "params":  "category=Gifts' OR 1=1--",
            "headers": "Host: 0a1234.web-security-academy.net",
            "method":  "GET",
        },
    },
    {
        "name":     "XSS",
        "expected": "xss",
        "request":  {
            "url":     "https://0a1234.web-security-academy.net:443/filter?category=<script>alert(1)</script>",
            "params":  "category=<script>alert(1)</script>",
            "headers": "Host: 0a1234.web-security-academy.net",
            "method":  "GET",
        },
    },
    {
        "name":     "Command injection",
        "expected": "cmdi",
        "request":  {
            "url":     "https://0a1234.web-security-academy.net:443/filter?category=Gifts|whoami",
            "params":  "category=Gifts|whoami",
            "headers": "Host: 0a1234.web-security-academy.net",
            "method":  "GET",
        },
    },
    {
        "name":     "Path traversal",
        "expected": "traversal",
        "request":  {
            "url":     "https://0a1234.web-security-academy.net:443/filter?category=../../../../etc/passwd",
            "params":  "category=../../../../etc/passwd",
            "headers": "Host: 0a1234.web-security-academy.net",
            "method":  "GET",
        },
    },
]


def run_tests():
    print("=" * 55)
    print(" Web Attack Detector — Detection Tests")
    print("=" * 55)
    try:
        ad = AnomalyDetector.load()
        ac = AttackClassifier.load()
    except FileNotFoundError:
        print("ERROR: models not found. Run train.py first.")
        sys.exit(1)

    passed = 0
    for tc in TEST_CASES:
        req   = tc["request"]
        X     = extract_features(req).reshape(1, -1)
        labels, confs = ac.predict(X)
        label = labels[0]
        conf  = confs[0] * 100
        is_anomaly = ad.predict(X)[0]
        ok    = (label == tc["expected"] or
                (tc["expected"] != "normal" and is_anomaly))
        status = "PASS" if ok else "FAIL"
        if ok:
            passed += 1
        print(f"  [{status}] {tc['name']:<25} -> {label:<20} ({conf:.1f}%)")

    print("-" * 55)
    print(f"  Result: {passed}/{len(TEST_CASES)} tests passed")
    print("=" * 55)


if __name__ == "__main__":
    run_tests()
