"""Test the full detection engine with QML enabled."""

import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from detection_engine import DetectionEngine
from tests.comprehensive_test import TEST_CASES

ATTACK_TYPES = {"sqli", "xss", "cmdi", "traversal"}

engine = DetectionEngine(use_qml=True)

passed = 0
failed = 0
failures = []
qml_used_count = 0
results_by_cat = {}

for tc in TEST_CASES:
    name = tc["name"]
    expected = tc["expected"]
    cat_parts = name.split(" — ")
    category = cat_parts[0].strip() if len(cat_parts) > 1 else "Other"

    result = engine.analyze(tc["request"])
    label = result["label"]
    conf = result["confidence"]
    stage = result["stage"]
    is_anomaly = result["details"].get("anomaly_flag", False)
    used_qml = "quantum" in stage.lower()

    if used_qml:
        qml_used_count += 1

    if expected == "normal":
        ok = label == "normal"
    else:
        ok = (label == expected or
              (label in ATTACK_TYPES and expected in ATTACK_TYPES) or
              label == "suspicious (zero-day?)")

    if ok:
        passed += 1
    else:
        failed += 1
        failures.append((name, expected, label, conf, stage))

    if category not in results_by_cat:
        results_by_cat[category] = {"passed": 0, "failed": 0, "total": 0}
    results_by_cat[category]["total"] += 1
    if ok:
        results_by_cat[category]["passed"] += 1
    else:
        results_by_cat[category]["failed"] += 1

    status = "OK" if ok else "FAIL"
    qml_flag = " [QML]" if used_qml else ""
    anomaly_flag = " [ANOMALY]" if is_anomaly else ""
    print(f"  [{status:>4}] {name:<50} exp={expected:<12} got={label:<20} conf={conf:5.1f}%  stage={stage}{anomaly_flag}{qml_flag}")

print()
print("=" * 100)
print("  RESULTS SUMMARY (with full Detection Engine + QML)")
print("=" * 100)

total = len(TEST_CASES)
print(f"  Overall: {passed}/{total} passed  ({100*passed/total:.1f}%)")
if failed > 0:
    print(f"  Failed:  {failed}/{total}")
print(f"  QML used in: {qml_used_count}/{total} cases ({100*qml_used_count/total:.1f}%)")

print()
cats = sorted(results_by_cat.keys())
print(f"  {'Category':<25} {'Passed':>8} {'Failed':>8} {'Total':>8} {'Rate':>8}")
print("  " + "-" * 60)
for cat in cats:
    r = results_by_cat[cat]
    rate = 100 * r["passed"] / r["total"] if r["total"] > 0 else 0
    print(f"  {cat:<25} {r['passed']:>8} {r['failed']:>8} {r['total']:>8} {rate:>7.1f}%")

if failures:
    print()
    print(f"  FAILURES ({len(failures)}):")
    print("  " + "-" * 70)
    for name, expected, got, conf, stage in failures:
        print(f"    {name}")
        print(f"      Expected: {expected:<12} Got: {got:<20} Conf: {conf:.1f}%  Stage: {stage}")

print("=" * 100)
