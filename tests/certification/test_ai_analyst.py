import pytest
import requests
import uuid

BASE_URL = "http://127.0.0.1:8000/api/v1"

def test_ai_analyst_success_path():
    # 1. Fetch an active threat
    res = requests.get(f"{BASE_URL}/response/threats?page=1&page_size=1")
    assert res.status_code == 200
    data = res.json()
    
    if not data.get("items"):
        pytest.skip("No threats available for AI testing")
        
    target = data["items"][0]
    alert_id = target["alert_id"]
    ip = target["source_ip"]
    score = target["threat_score"]
    
    # 2. Ask AI to summarize the exact alert
    chat_payload = {
        "session_id": str(uuid.uuid4()),
        "message": f"Please summarize alert {alert_id}",
    }
    chat_res = requests.post(f"{BASE_URL}/copilot/chat", json=chat_payload)
    assert chat_res.status_code == 200
    ai_response = chat_res.json().get("response", "")
    
    # 3. Assert exact data fidelity in the LLM response
    assert alert_id in ai_response, "AI Hallucination: Missing exact Alert ID"
    assert ip in ai_response, "AI Hallucination: Missing exact IP Address"
    
    score_fmt = f"{score:.2f}"
    score_int = str(int(score))
    assert score_fmt in ai_response or score_int in ai_response, "AI Hallucination: Missing exact Threat Score"

def test_ai_analyst_failure_path():
    fake_id = str(uuid.uuid4())
    chat_payload = {
        "session_id": str(uuid.uuid4()),
        "message": f"Explain alert {fake_id}",
    }
    chat_res = requests.post(f"{BASE_URL}/copilot/chat", json=chat_payload)
    
    # The API might return 404, or the LLM might gracefully say it doesn't exist.
    # The requirement: "Expected: Alert not found, Not: Here's a likely explanation"
    if chat_res.status_code == 200:
        reply = chat_res.json().get("response", "").lower()
        assert "not found" in reply or "cannot find" in reply or "does not exist" in reply or "don't have" in reply or "no data" in reply or "not aware" in reply or "no alert" in reply or "don't see" in reply
    else:
        assert chat_res.status_code == 404
