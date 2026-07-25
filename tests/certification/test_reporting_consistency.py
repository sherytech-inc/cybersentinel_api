import pytest
import requests
import asyncio
from app.database.client import get_db_client

BASE_URL = "http://127.0.0.1:8000/api/v1"

def test_reporting_consistency_after_injection():
    # 1. Inject Port Scan
    inject_res = requests.post(f"{BASE_URL}/demo/load?scenario=port_scan", timeout=30)
    assert inject_res.status_code == 200
    
    # 2. Get Threat Response Count (active threats)
    threat_res = requests.get(f"{BASE_URL}/response/overview", timeout=30)
    assert threat_res.status_code == 200
    threat_count = threat_res.json().get("active_threats", 0)
    
    # 3. Get Dashboard/Reports Count
    dash_res = requests.get(f"{BASE_URL}/dashboard/stats", timeout=30)
    # if the endpoint is different, e.g., /reporting/dashboard
    if dash_res.status_code == 404:
        dash_res = requests.get(f"{BASE_URL}/reporting/dashboard", timeout=30)
        
    assert dash_res.status_code == 200
    report_threat_count = dash_res.json().get("snapshot", {}).get("active_threats", 0)
    
    # Ensure they match
    assert threat_count == report_threat_count, f"Mismatch: Response={threat_count}, Reports={report_threat_count}"
    
    # 4. Check PDF Export
    pdf_res = requests.get(f"{BASE_URL}/reporting/export/pdf", timeout=15)
    assert pdf_res.status_code == 200
    assert pdf_res.headers["content-type"] == "application/pdf"
    
    # Check CSV Export
    csv_res = requests.get(f"{BASE_URL}/reporting/export/csv?type=alerts")
    assert csv_res.status_code == 200
    assert "text/csv" in csv_res.headers["content-type"]

@pytest.mark.asyncio
async def test_pdf_export_no_threats():
    # Make sure DB has no alerts to test empty state handling
    from app.database.client import get_db_client, init_db
    await init_db()
    client = await get_db_client()
    await client.table("threat_alerts").delete().neq("status", "fake_status_to_delete_all").execute()
    
    pdf_res = requests.get(f"{BASE_URL}/reporting/export/pdf", timeout=15)
    assert pdf_res.status_code == 200
    # Ideally, we parse the PDF or the backend returns a placeholder PDF.
    # The requirement is it doesn't crash and returns 200.
