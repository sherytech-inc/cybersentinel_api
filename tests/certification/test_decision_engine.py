import pytest
from app.scoring.threat_score import compute_threat_score
from app.schemas.decision import Model1Input, Model2Input, Model3Input, PredictionLabel

def test_decision_engine_weights_and_sum():
    # Test Normal
    m1 = Model1Input(prediction=PredictionLabel.NORMAL, confidence=0.9)
    m2 = Model2Input(anomaly_score=10.0)
    m3 = Model3Input(intel_score=5.0, abuse_score=0, vt_malicious=0, vt_total_engines=0, is_tor=False, is_whitelisted=False, intel_severity="Safe")
    
    result = compute_threat_score(m1, m2, m3)
    
    # Verify the sum matches final score (assuming no clamp)
    expected_sum = result.breakdown.model1_contribution + result.breakdown.model2_contribution + result.breakdown.model3_contribution
    assert round(expected_sum, 2) == round(result.final_score, 2)

def test_decision_engine_clamp():
    # Test Malicious
    m1 = Model1Input(prediction=PredictionLabel.MALICIOUS, confidence=1.0)
    m2 = Model2Input(anomaly_score=100.0)
    m3 = Model3Input(intel_score=100.0, abuse_score=100, vt_malicious=10, vt_total_engines=10, is_tor=False, is_whitelisted=False, intel_severity="Critical")
    
    result = compute_threat_score(m1, m2, m3)
    
    assert result.final_score <= 100.0

def test_decision_engine_overrides():
    # Test Whitelisted
    m1 = Model1Input(prediction=PredictionLabel.MALICIOUS, confidence=1.0)
    m2 = Model2Input(anomaly_score=100.0)
    m3 = Model3Input(intel_score=100.0, abuse_score=0, vt_malicious=0, vt_total_engines=0, is_tor=False, is_whitelisted=True, intel_severity="Safe")
    
    result = compute_threat_score(m1, m2, m3)
    
    # Should cap at 10 due to whitelist
    assert result.final_score <= 10.0
