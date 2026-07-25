import pytest
import requests
import uuid

BASE_URL = "http://127.0.0.1:8000/api/v1"

def test_investigation_data_fidelity():
    res = requests.get(f"{BASE_URL}/response/threats?page=1&page_size=1")
    assert res.status_code == 200
    data = res.json()
    if not data.get("items"):
        pytest.skip("No threats to test investigation")
        
    target = data["items"][0]
    alert_id = target["alert_id"]
    
    # Let's hit the endpoint the investigation screen uses
    inv_res = requests.get(f"{BASE_URL}/threats/{alert_id}")
    if inv_res.status_code == 404:
        inv_res = requests.get(f"{BASE_URL}/response/threats/{alert_id}")
        
    assert inv_res.status_code == 200
    inv_data = inv_res.json()
    
    assert inv_data["source_ip"] == target["source_ip"]
    assert inv_data["severity"] == target["severity"]
    assert str(inv_data["threat_score"]) == str(target["threat_score"])
    
    # Test investigate with AI
    chat_payload = {
        "session_id": str(uuid.uuid4()),
        "message": f"Please explain alert {alert_id}"
    }
    chat_res = requests.post(f"{BASE_URL}/copilot/chat", json=chat_payload)
    assert chat_res.status_code == 200
    
    # We assert AI output is aligned with DB explainability
    explain_res = requests.get(f"{BASE_URL}/response/threats/{alert_id}/explanation")
    if explain_res.status_code == 200:
        exp_data = explain_res.json()
        breakdown = exp_data.get("breakdown", {})
        score = inv_data["threat_score"]
        score_str = str(score)
        # Depending on how the AI formats it, it should at least mention the ID
        assert alert_id in chat_res.json().get("response", "")
        assert score_str[:4] in chat_res.json().get("response", "") or str(int(score)) in chat_res.json().get("response", ""), "Investigation assistant did not cite exact threat score"

def test_investigation_404():
    res = requests.get(f"{BASE_URL}/threats/non-existent-alert-id")
    if res.status_code == 404:
        assert res.status_code == 404
    else:
        res2 = requests.get(f"{BASE_URL}/response/threats/non-existent-alert-id")
        assert res2.status_code == 404
