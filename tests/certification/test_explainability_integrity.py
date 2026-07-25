import pytest
import requests

BASE_URL = "http://127.0.0.1:8000/api/v1"

def test_explainability_matches_db():
    # 1. Fetch a real threat from DB via API
    res = requests.get(f"{BASE_URL}/response/threats?page=1&page_size=5")
    assert res.status_code == 200
    data = res.json()
    
    if not data.get("items"):
        pytest.skip("No active threats to test explainability against.")
        
    target_alert = data["items"][0]
    alert_id = target_alert["alert_id"]
    
    # 2. Fetch Explainability Service breakdown
    explain_res = requests.get(f"{BASE_URL}/response/threats/{alert_id}/explanation")
    assert explain_res.status_code == 200
    explanation = explain_res.json()
    
    # 3. Assert values match the reality stored in the DB row
    assert explanation["alert_id"] == alert_id
    assert explanation["threat_score"] == target_alert["threat_score"]
    
    breakdown = explanation.get("breakdown", {})
    # Match the model scores
    # If the alert doesn't have model scores, it defaults to 0.0
    expected_rf = target_alert.get("model1_score") or 0.0
    expected_iso = target_alert.get("model2_score") or 0.0
    expected_intel = target_alert.get("model3_score") or 0.0
    
    assert breakdown.get("random_forest", {}).get("raw_score") == expected_rf
    assert breakdown.get("isolation_forest", {}).get("raw_score") == expected_iso
    assert breakdown.get("threat_intelligence", {}).get("raw_score") == expected_intel
