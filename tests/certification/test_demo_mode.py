import pytest
import requests
import time
import uuid

BASE_URL = "http://127.0.0.1:8000/api/v1"

def test_demo_pipeline_propagation():
    # 1. Fetch current counts
    res = requests.get(f"{BASE_URL}/response/overview")
    assert res.status_code == 200
    initial_threats = res.json().get("active_threats", 0)
    
    # 2. Inject Demo Scenario
    inject_res = requests.post(f"{BASE_URL}/demo/load?scenario=brute_force")
    assert inject_res.status_code == 200
    demo_data = inject_res.json()
    alert_id = demo_data["alert_id"]
    packets_injected = demo_data["packets_injected"]
    
    assert packets_injected > 0
    assert alert_id is not None
    
    # Allow a brief moment for DB to settle
    time.sleep(1)
    
    # 3. Verify Alerts Generated
    res2 = requests.get(f"{BASE_URL}/response/overview")
    assert res2.status_code == 200
    new_threats = res2.json().get("active_threats", 0)
    assert new_threats > initial_threats, "Alerts did not propagate to Threat Response"
    
    # 4. Verify AI Analyst sees it
    chat_payload = {
        "session_id": str(uuid.uuid4()),
        "message": f"Summarize alert {alert_id}"
    }
    chat_res = requests.post(f"{BASE_URL}/copilot/chat", json=chat_payload)
    assert chat_res.status_code == 200
    assert alert_id in chat_res.json().get("response", ""), "AI Analyst cannot see the injected alert"
    
    # 5. Verify Investigation Workspace sees it
    inv_res = requests.get(f"{BASE_URL}/threats/{alert_id}")
    if inv_res.status_code == 404:
        inv_res = requests.get(f"{BASE_URL}/response/threats/{alert_id}")
    assert inv_res.status_code == 200, "Investigation Workspace cannot see the injected alert"
