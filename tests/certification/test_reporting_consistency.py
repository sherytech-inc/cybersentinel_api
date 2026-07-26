import os

import pytest
import requests

BASE_URL = os.getenv("CYBERSENTINEL_API_URL", "http://127.0.0.1:8000/api/v1")


def _authenticated_headers() -> dict[str, str]:
    access_token = os.getenv("SUPABASE_ACCESS_TOKEN")
    local_token = os.getenv("CYBERSENTINEL_LOCAL_TOKEN")
    if not access_token or not local_token:
        pytest.skip("Signed-in certification credentials are not configured")
    return {
        "Authorization": f"Bearer {access_token}",
        "X-CyberSentinel-Local-Token": local_token,
    }


def test_reporting_consistency_after_injection():
    headers = _authenticated_headers()

    # 1. Inject Port Scan
    inject_res = requests.post(
        f"{BASE_URL}/demo/load?scenario=port_scan",
        headers=headers,
        timeout=30,
    )
    assert inject_res.status_code == 200

    # 2. Get Threat Response Count (active threats)
    threat_res = requests.get(
        f"{BASE_URL}/response/overview",
        headers=headers,
        timeout=30,
    )
    assert threat_res.status_code == 200
    threat_count = threat_res.json().get("active_threats", 0)

    # 3. The normalized report exposes the same persisted active alerts.
    summary_res = requests.get(
        f"{BASE_URL}/reporting/summary",
        headers=headers,
        timeout=30,
    )
    assert summary_res.status_code == 200
    summary = summary_res.json()
    report_threat_count = sum(
        1
        for alert in summary["recent_alerts"]
        if str(alert.get("status", "")).upper() in {"OPEN", "INVESTIGATING"}
    )
    assert threat_count == report_threat_count, (
        f"Mismatch: Response={threat_count}, Reports={report_threat_count}"
    )

    # 4. Check PDF Export
    pdf_res = requests.get(
        f"{BASE_URL}/reporting/export/pdf",
        headers=headers,
        timeout=15,
    )
    assert pdf_res.status_code == 200
    assert pdf_res.headers["content-type"] == "application/pdf"

    # Check canonical Alerts CSV export.
    csv_res = requests.get(
        f"{BASE_URL}/reporting/export/alerts.csv",
        headers=headers,
        timeout=15,
    )
    assert csv_res.status_code == 200
    assert "text/csv" in csv_res.headers["content-type"]



def test_pdf_export_is_a_valid_attachment():
    headers = _authenticated_headers()
    pdf_res = requests.get(
        f"{BASE_URL}/reporting/export/pdf",
        headers=headers,
        timeout=15,
    )
    assert pdf_res.status_code == 200
    assert pdf_res.content.startswith(b"%PDF-")
    assert b"%%EOF" in pdf_res.content
    assert "attachment;" in pdf_res.headers["content-disposition"]
