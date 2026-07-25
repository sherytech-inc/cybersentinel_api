import subprocess
import json
import os
from datetime import datetime, timezone

def run_test(test_file: str) -> str:
    print(f"Running {test_file}...")
    result = subprocess.run(
        ["venv/bin/pytest", f"tests/certification/{test_file}", "-v", "--disable-warnings"],
        cwd="/Users/shehrozali/cybersentinel_api",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    if result.returncode == 0:
        print(f"✅ {test_file} PASSED")
        return "PASS"
    elif result.returncode == 5: # No tests collected / skipped
        print(f"⚠️ {test_file} SKIPPED (No data?)")
        return "SKIP"
    else:
        print(f"❌ {test_file} FAILED")
        print(result.stdout)
        return "FAIL"

def main():
    report = {
        "ai_validation": run_test("test_ai_analyst.py"),
        "reporting_validation": run_test("test_reporting_consistency.py"),
        "investigation_validation": run_test("test_investigation.py"),
        "decision_engine_validation": run_test("test_decision_engine.py"),
        "explainability_validation": run_test("test_explainability_integrity.py"),
        "websocket_validation": run_test("test_websocket_events.py"),
        "demo_mode_validation": run_test("test_demo_mode.py"),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    report_path = "/Users/shehrozali/cybersentinel_api/certification_report.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n=========================================")
    print(f"Certification Complete. Report saved to:")
    print(f"{report_path}")
    print(f"=========================================\n")
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
