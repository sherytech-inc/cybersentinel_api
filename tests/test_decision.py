"""
CyberSentinel — Model 4 Complete Test Suite
=============================================
Covers all architecture spec cases:

  Case 1: RF=Normal  IF=low   Intel=0   → ALLOW  (clean)
  Case 2: RF=Normal  IF=high  Intel=0   → INVESTIGATE (weird behaviour)
  Case 3: RF=Normal  IF=low   Intel=95  → ALERT  (known bad IP)
  Case 4: RF=Malicious IF=high Intel=95 → BLOCK  (all agree)

Run: pytest tests/test_decision.py -v
"""
import pytest
from fastapi.testclient import TestClient

from app.schemas.decision import (
    AnalyzeRequest, DecisionResponse,
    Model1Input, Model2Input, Model3Input,
    PredictionLabel, ThreatSeverity, RecommendedAction,
)
from app.scoring.severity import classify_severity, classify_action
from app.scoring.threat_score import (
    compute_threat_score, _clamp, _score_model1,
    _score_model2, _score_model3, _resolve_weights,
)
from app.scoring.recommendations import build_explanation
from app.services.decision.engine import DecisionEngineService


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def engine():
    return DecisionEngineService()

@pytest.fixture
def m1_normal():
    return Model1Input(prediction="Normal", confidence=0.98)

@pytest.fixture
def m1_suspicious():
    return Model1Input(prediction="Suspicious", confidence=0.80)

@pytest.fixture
def m1_malicious():
    return Model1Input(prediction="Malicious", confidence=0.96)

@pytest.fixture
def m2_low():
    return Model2Input(anomaly_score=12.0)

@pytest.fixture
def m2_high():
    return Model2Input(anomaly_score=92.0)

@pytest.fixture
def m3_clean():
    return Model3Input(
        abuse_score=0.0, vt_malicious=0, vt_total_engines=70,
        intel_score=0.0, intel_severity="Safe",
    )

@pytest.fixture
def m3_critical():
    return Model3Input(
        abuse_score=91.0, abuse_total_reports=125, abuse_distinct_users=40,
        vt_malicious=23, vt_suspicious=3, vt_total_engines=70,
        intel_score=95.0, intel_severity="Critical",
        country="Russia", is_proxy=True,
    )

@pytest.fixture
def breakdown_factory():
    from app.schemas.decision import ScoreBreakdown
    def _make(**kw):
        defaults = dict(
            model1_raw_score=50, model2_raw_score=50, model3_raw_score=50,
            model1_contribution=25, model2_contribution=10, model3_contribution=15,
            model1_weight=0.5, model2_weight=0.2, model3_weight=0.3,
        )
        defaults.update(kw)
        return ScoreBreakdown(**defaults)
    return _make


# ── 1. Schema Validation ──────────────────────────────────────────────────────

class TestSchemaValidation:
    def test_model1_valid(self):
        m = Model1Input(prediction="Malicious", confidence=0.9)
        assert m.prediction == PredictionLabel.MALICIOUS

    def test_model1_confidence_clamped_above_1(self):
        assert Model1Input(prediction="Normal", confidence=1.5).confidence == 1.0

    def test_model1_confidence_clamped_below_0(self):
        assert Model1Input(prediction="Normal", confidence=-0.5).confidence == 0.0

    def test_model1_invalid_label_rejected(self):
        with pytest.raises(Exception):
            Model1Input(prediction="Unknown", confidence=0.5)

    def test_model2_clamped_above_100(self):
        assert Model2Input(anomaly_score=150).anomaly_score == 100.0

    def test_model2_clamped_below_0(self):
        assert Model2Input(anomaly_score=-5).anomaly_score == 0.0

    def test_model3_accepts_full_rich_fields(self):
        m3 = Model3Input(
            abuse_score=91.0, intel_score=95.0, intel_severity="Critical",
            vt_malicious=23, vt_total_engines=70, is_tor=True,
        )
        assert m3.intel_score == 95.0
        assert m3.is_tor is True

    def test_analyze_request_model3_optional(self):
        req = AnalyzeRequest(
            model1=Model1Input(prediction="Normal", confidence=0.9),
            model2=Model2Input(anomaly_score=5.0),
        )
        assert req.model3 is None

    def test_analyze_request_with_ip(self):
        req = AnalyzeRequest(
            model1=Model1Input(prediction="Malicious", confidence=0.9),
            model2=Model2Input(anomaly_score=80.0),
            source_ip="185.220.101.45",
        )
        assert req.source_ip == "185.220.101.45"


# ── 2. Scoring Math ───────────────────────────────────────────────────────────

class TestScoringMath:
    def test_clamp_upper(self):
        assert _clamp(150.0) == 100.0

    def test_clamp_lower(self):
        assert _clamp(-10.0) == 0.0

    def test_model1_malicious_full_confidence_is_100(self):
        assert _score_model1(Model1Input(prediction="Malicious", confidence=1.0)) == 100.0

    def test_model1_normal_is_always_zero(self):
        assert _score_model1(Model1Input(prediction="Normal", confidence=1.0)) == 0.0

    def test_model1_suspicious_half(self):
        assert _score_model1(Model1Input(prediction="Suspicious", confidence=1.0)) == 50.0

    def test_model1_scales_by_confidence(self):
        assert _score_model1(Model1Input(prediction="Malicious", confidence=0.5)) == 50.0

    def test_model2_passthrough(self):
        assert _score_model2(Model2Input(anomaly_score=73.5)) == 73.5

    def test_model3_uses_intel_score_directly(self):
        m3 = Model3Input(abuse_score=50, intel_score=91.0, vt_malicious=0, vt_total_engines=0)
        assert _score_model3(m3) == 91.0

    def test_model3_recomputes_when_intel_score_zero(self):
        # abuse=100, vt=70/70=100 → 0.7*100 + 0.3*100 = 100
        m3 = Model3Input(abuse_score=100, intel_score=0, vt_malicious=70, vt_total_engines=70)
        assert _score_model3(m3) == 100.0

    def test_model3_none_returns_zero(self):
        assert _score_model3(None) == 0.0

    def test_weights_with_model3_sum_to_one(self):
        w1, w2, w3 = _resolve_weights(True)
        assert w1 + w2 + w3 == pytest.approx(1.0)

    def test_weights_without_model3_sum_to_one(self):
        w1, w2, w3 = _resolve_weights(False)
        assert w3 == 0.0
        assert w1 + w2 == pytest.approx(1.0)

    def test_final_score_always_in_range(self, m1_malicious, m2_high, m3_critical):
        r = compute_threat_score(m1_malicious, m2_high, m3_critical)
        assert 0.0 <= r.final_score <= 100.0

    def test_all_zeros_gives_zero(self):
        r = compute_threat_score(
            Model1Input(prediction="Normal", confidence=1.0),
            Model2Input(anomaly_score=0.0),
            Model3Input(abuse_score=0, intel_score=0, vt_malicious=0, vt_total_engines=0),
        )
        assert r.final_score == 0.0

    def test_breakdown_contributions_sum_to_final(self, m1_malicious, m2_high, m3_critical):
        r = compute_threat_score(m1_malicious, m2_high, m3_critical)
        bd = r.breakdown
        total = bd.model1_contribution + bd.model2_contribution + bd.model3_contribution
        assert total == pytest.approx(r.final_score, abs=5.0)  # overrides may shift final

    def test_tor_floor_applied(self, m1_normal, m2_low):
        m3_tor = Model3Input(
            abuse_score=5.0, intel_score=5.0, is_tor=True,
        )
        r = compute_threat_score(m1_normal, m2_low, m3_tor)
        assert r.final_score >= 76.0

    def test_whitelist_cap_applied(self, m1_malicious, m2_high):
        m3_wl = Model3Input(
            abuse_score=95.0, intel_score=95.0, is_whitelisted=True,
        )
        r = compute_threat_score(m1_malicious, m2_high, m3_wl)
        assert r.final_score <= 10.0


# ── 3. Severity & Action Bands ────────────────────────────────────────────────

class TestSeverityAction:
    def test_score_0_is_safe_allow(self):
        assert classify_severity(0.0) == ThreatSeverity.SAFE
        assert classify_action(0.0) == RecommendedAction.ALLOW

    def test_score_25_is_safe_allow(self):
        assert classify_severity(25.0) == ThreatSeverity.SAFE
        assert classify_action(25.0) == RecommendedAction.ALLOW

    def test_score_26_is_low_monitor(self):
        assert classify_severity(26.0) == ThreatSeverity.LOW
        assert classify_action(26.0) == RecommendedAction.MONITOR

    def test_score_50_is_low_monitor(self):
        assert classify_severity(50.0) == ThreatSeverity.LOW
        assert classify_action(50.0) == RecommendedAction.MONITOR

    def test_score_51_is_medium_investigate(self):
        assert classify_severity(51.0) == ThreatSeverity.MEDIUM
        assert classify_action(51.0) == RecommendedAction.INVESTIGATE

    def test_score_75_is_medium_investigate(self):
        assert classify_severity(75.0) == ThreatSeverity.MEDIUM
        assert classify_action(75.0) == RecommendedAction.INVESTIGATE

    def test_score_76_is_high_alert(self):
        assert classify_severity(76.0) == ThreatSeverity.HIGH
        assert classify_action(76.0) == RecommendedAction.ALERT

    def test_score_90_is_high_alert(self):
        assert classify_severity(90.0) == ThreatSeverity.HIGH
        assert classify_action(90.0) == RecommendedAction.ALERT

    def test_score_91_is_critical_block(self):
        assert classify_severity(91.0) == ThreatSeverity.CRITICAL
        assert classify_action(91.0) == RecommendedAction.BLOCK

    def test_score_100_is_critical_block(self):
        assert classify_severity(100.0) == ThreatSeverity.CRITICAL
        assert classify_action(100.0) == RecommendedAction.BLOCK


# ── 4. Architecture Spec Cases ────────────────────────────────────────────────

class TestArchitectureSpecCases:
    """
    Four canonical test cases from the architecture document.
    These are the source-of-truth for the entire Decision Engine.
    """
    def test_case1_clean_traffic(self, engine):
        """RF=Normal, IF=12, Intel=0 → low score → ALLOW"""
        req = AnalyzeRequest(
            model1=Model1Input(prediction="Normal", confidence=0.98),
            model2=Model2Input(anomaly_score=12.0),
            model3=Model3Input(abuse_score=0, intel_score=0, vt_malicious=0, vt_total_engines=0),
        )
        resp = engine.analyze(req)
        assert resp.final_score <= 25.0
        assert resp.recommended_action == RecommendedAction.ALLOW
        assert resp.final_severity == ThreatSeverity.SAFE

    def test_case2_weird_behaviour(self, engine):
        """RF=Normal, IF=92, no Intel → MONITOR (anomaly weight redistributed)"""
        req = AnalyzeRequest(
            model1=Model1Input(prediction="Normal", confidence=0.95),
            model2=Model2Input(anomaly_score=92.0),
        )
        resp = engine.analyze(req)
        # No m3: w1=0.714 w2=0.286 => 0*0.714 + 92*0.286 = 26.3 => LOW => MONITOR
        assert resp.final_score >= 20.0
        assert resp.recommended_action in (
            RecommendedAction.MONITOR, RecommendedAction.INVESTIGATE
        )

    def test_case3_known_bad_ip(self, engine):
        """RF=Normal, IF=10, Intel=95 → Critical / BLOCK (intel blacklist override)"""
        req = AnalyzeRequest(
            model1=Model1Input(prediction="Normal", confidence=0.97),
            model2=Model2Input(anomaly_score=10.0),
            model3=Model3Input(
                abuse_score=91.0, intel_score=95.0, intel_severity="Critical",
                vt_malicious=23, vt_total_engines=70,
            ),
            source_ip="185.220.101.45",
        )
        resp = engine.analyze(req)
        assert resp.final_score == 95.0
        assert resp.recommended_action == RecommendedAction.BLOCK
        assert resp.final_severity == ThreatSeverity.CRITICAL

    def test_case4_all_agree_block(self, engine):
        """RF=Malicious, IF=90, Intel=95 → Block (everything agrees)"""
        req = AnalyzeRequest(
            model1=Model1Input(prediction="Malicious", confidence=0.96),
            model2=Model2Input(anomaly_score=90.0),
            model3=Model3Input(
                abuse_score=91.0, intel_score=95.0, intel_severity="Critical",
                vt_malicious=23, vt_total_engines=70, is_proxy=True,
            ),
            source_ip="185.220.101.45",
        )
        resp = engine.analyze(req)
        # M1=96*0.5=48, M2=90*0.2=18, M3=95*0.3=28.5 → 94.5 + convergence boost
        assert resp.final_score >= 90.0
        assert resp.recommended_action == RecommendedAction.BLOCK
        assert resp.final_severity == ThreatSeverity.CRITICAL


# ── 5. Full Pipeline Service ──────────────────────────────────────────────────

class TestDecisionEngineService:
    def test_response_has_all_required_fields(self, engine, m1_malicious, m2_high, m3_critical):
        req = AnalyzeRequest(model1=m1_malicious, model2=m2_high, model3=m3_critical)
        resp = engine.analyze(req)
        assert isinstance(resp, DecisionResponse)
        assert resp.final_score is not None
        assert resp.final_severity is not None
        assert resp.recommended_action is not None
        assert len(resp.explanation) > 0
        assert resp.score_breakdown is not None

    def test_model3_absent_still_works(self, engine, m1_malicious, m2_high):
        req = AnalyzeRequest(model1=m1_malicious, model2=m2_high)
        resp = engine.analyze(req)
        assert resp.model3_available is False
        assert resp.model3 is None
        assert 0.0 <= resp.final_score <= 100.0

    def test_source_ip_propagated(self, engine, m1_normal, m2_low):
        req = AnalyzeRequest(model1=m1_normal, model2=m2_low, source_ip="8.8.8.8")
        resp = engine.analyze(req)
        assert resp.ip == "8.8.8.8"

    def test_model1_summary_in_response(self, engine, m1_malicious, m2_low):
        req = AnalyzeRequest(model1=m1_malicious, model2=m2_low)
        resp = engine.analyze(req)
        assert resp.model1.classification == "Malicious"
        assert resp.model1.confidence == 0.96

    def test_model2_summary_in_response(self, engine, m1_normal, m2_high):
        req = AnalyzeRequest(model1=m1_normal, model2=m2_high)
        resp = engine.analyze(req)
        assert resp.model2.threat_score == 92.0

    def test_model3_summary_in_response(self, engine, m1_normal, m2_low, m3_critical):
        req = AnalyzeRequest(model1=m1_normal, model2=m2_low, model3=m3_critical)
        resp = engine.analyze(req)
        assert resp.model3 is not None
        assert resp.model3.intel_score == 95.0
        assert resp.model3.severity == "Critical"

    def test_explanation_mentions_rf(self, engine, m1_malicious, m2_low):
        req = AnalyzeRequest(model1=m1_malicious, model2=m2_low)
        resp = engine.analyze(req)
        full = " ".join(resp.explanation).lower()
        assert "malicious" in full

    def test_explanation_mentions_anomaly(self, engine, m1_normal, m2_high):
        req = AnalyzeRequest(model1=m1_normal, model2=m2_high)
        resp = engine.analyze(req)
        full = " ".join(resp.explanation).lower()
        assert "anomal" in full

    def test_explanation_mentions_abuseipdb(self, engine, m1_normal, m2_low, m3_critical):
        req = AnalyzeRequest(model1=m1_normal, model2=m2_low, model3=m3_critical)
        resp = engine.analyze(req)
        full = " ".join(resp.explanation).lower()
        assert "abuseipdb" in full

    def test_breakdown_weights_sum_to_one(self, engine, m1_malicious, m2_high, m3_critical):
        req = AnalyzeRequest(model1=m1_malicious, model2=m2_high, model3=m3_critical)
        resp = engine.analyze(req)
        bd = resp.score_breakdown
        assert bd.model1_weight + bd.model2_weight + bd.model3_weight == pytest.approx(1.0)


# ── 6. API Routes ─────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def client():
    from app.main import app
    from app.services.intelligence.cache import init_cache
    init_cache(ttl_seconds=60, max_size=100)
    with TestClient(app) as c:
        yield c


_VALID_BODY = {
    "model1": {"prediction": "Malicious", "confidence": 0.96},
    "model2": {"anomaly_score": 90},
    "model3": {
        "abuse_score": 91, "abuse_total_reports": 125,
        "vt_malicious": 23, "vt_suspicious": 3, "vt_total_engines": 70,
        "intel_score": 95, "intel_severity": "Critical",
        "country": "Russia", "is_proxy": True,
    },
    "source_ip": "185.220.101.45",
}


class TestDecisionRoutes:
    def test_analyze_200(self, client):
        assert client.post("/api/v1/decision/analyze", json=_VALID_BODY).status_code == 200

    def test_response_has_final_score(self, client):
        d = client.post("/api/v1/decision/analyze", json=_VALID_BODY).json()
        assert "final_score" in d
        assert 0 <= d["final_score"] <= 100

    def test_response_has_final_severity(self, client):
        d = client.post("/api/v1/decision/analyze", json=_VALID_BODY).json()
        assert d["final_severity"] in ["Safe","Low","Medium","High","Critical"]

    def test_response_has_recommended_action(self, client):
        d = client.post("/api/v1/decision/analyze", json=_VALID_BODY).json()
        assert d["recommended_action"] in ["ALLOW","MONITOR","INVESTIGATE","ALERT","BLOCK"]

    def test_response_has_explanation_list(self, client):
        d = client.post("/api/v1/decision/analyze", json=_VALID_BODY).json()
        assert isinstance(d["explanation"], list) and len(d["explanation"]) > 0

    def test_response_has_model_summaries(self, client):
        d = client.post("/api/v1/decision/analyze", json=_VALID_BODY).json()
        assert "model1" in d and "model2" in d and "model3" in d

    def test_response_ip_matches_request(self, client):
        d = client.post("/api/v1/decision/analyze", json=_VALID_BODY).json()
        assert d["ip"] == "185.220.101.45"

    def test_without_model3_returns_200(self, client):
        body = {"model1": {"prediction": "Normal", "confidence": 0.99}, "model2": {"anomaly_score": 5}}
        d = client.post("/api/v1/decision/analyze", json=body).json()
        assert d["model3_available"] is False

    def test_missing_model1_returns_422(self, client):
        assert client.post("/api/v1/decision/analyze", json={"model2": {"anomaly_score": 50}}).status_code == 422

    def test_invalid_prediction_label_returns_422(self, client):
        body = {"model1": {"prediction": "BadLabel", "confidence": 0.9}, "model2": {"anomaly_score": 50}}
        assert client.post("/api/v1/decision/analyze", json=body).status_code == 422

    def test_health_200(self, client):
        r = client.get("/api/v1/decision/health")
        assert r.status_code == 200 and r.json()["status"] == "ok"

    def test_weights_200(self, client):
        r = client.get("/api/v1/decision/weights")
        assert r.status_code == 200
        assert "model1_random_forest" in r.json()

    def test_thresholds_200(self, client):
        r = client.get("/api/v1/decision/thresholds")
        assert r.status_code == 200
        assert "severity" in r.json() and "action" in r.json()


class TestSIEMOverrides:
    def test_scenario_a_safe_dns(self, engine):
        req = AnalyzeRequest(
            model1=Model1Input(prediction="Normal", confidence=0.98),
            model2=Model2Input(anomaly_score=10.0),
            model3=Model3Input(
                abuse_score=0.0, vt_malicious=0, vt_total_engines=70,
                intel_score=0.0, intel_severity="Safe",
                country="US", is_proxy=False, blacklisted=False
            ),
            source_ip="8.8.8.8"
        )
    def test_scenario_a_safe_dns(self, engine):
        req = AnalyzeRequest(
            model1=Model1Input(prediction="Normal", confidence=0.98),
            model2=Model2Input(anomaly_score=10.0),
            model3=Model3Input(
                abuse_score=0.0, vt_malicious=0, vt_total_engines=70,
                intel_score=0.0, intel_severity="Safe",
                country="US", is_proxy=False, blacklisted=False
            ),
            source_ip="8.8.8.8"
        )
        resp = engine.analyze(req)
        assert resp.final_severity == "Safe"
        assert resp.recommended_action == "ALLOW"
        assert resp.final_score <= 25.0

    def test_scenario_b_blacklisted_ip(self, engine):
        req = AnalyzeRequest(
            model1=Model1Input(prediction="Normal", confidence=0.98),
            model2=Model2Input(anomaly_score=10.0),
            model3=Model3Input(
                abuse_score=0.0, vt_malicious=0, vt_total_engines=70,
                intel_score=0.0, intel_severity="Safe",
                country="US", is_proxy=False, blacklisted=True
            ),
            source_ip="1.2.3.4"
        )
        resp = engine.analyze(req)
        assert resp.final_severity == "Critical"
        assert resp.recommended_action == "BLOCK"
        assert resp.final_score == 95.0
        assert "IP present in threat intelligence blacklists" in " ".join(resp.explanation)

    def test_scenario_c_zero_day_behavior(self, engine):
        req = AnalyzeRequest(
            model1=Model1Input(prediction="Normal", confidence=0.98),
            model2=Model2Input(anomaly_score=97.0),
            model3=Model3Input(
                abuse_score=0.0, vt_malicious=0, vt_total_engines=70,
                intel_score=0.0, intel_severity="Safe",
                country="US", is_proxy=False, blacklisted=False
            ),
            source_ip="1.2.3.4"
        )
        resp = engine.analyze(req)
        assert resp.final_severity == "Medium"
        assert resp.recommended_action == "MONITOR"
        assert resp.final_score == 55.0
        assert "standalone behavioral anomaly detected" in " ".join(resp.explanation).lower()

    def test_scenario_d_rf_attack_signature(self, engine):
        req = AnalyzeRequest(
            model1=Model1Input(prediction="Malicious", confidence=0.96),
            model2=Model2Input(anomaly_score=10.0),
            model3=Model3Input(
                abuse_score=0.0, vt_malicious=0, vt_total_engines=70,
                intel_score=0.0, intel_severity="Safe",
                country="US", is_proxy=False, blacklisted=False
            ),
            source_ip="1.2.3.4"
        )
        resp = engine.analyze(req)
        assert resp.final_severity == "High"
        assert resp.recommended_action == "INVESTIGATE"
        assert resp.final_score >= 75.0
        assert "high-confidence attack signature detected by rf" in " ".join(resp.explanation).lower()

    def test_scenario_d_rf_attack_signature_low_confidence_no_override(self, engine):
        req = AnalyzeRequest(
            model1=Model1Input(prediction="Malicious", confidence=0.51),
            model2=Model2Input(anomaly_score=10.0),
            model3=Model3Input(
                abuse_score=0.0, vt_malicious=0, vt_total_engines=70,
                intel_score=0.0, intel_severity="Safe",
                country="US", is_proxy=False, blacklisted=False
            ),
            source_ip="1.2.3.4"
        )
        resp = engine.analyze(req)
        # Should not trigger the override (so no BLOCK/INVESTIGATE override, just base math)
        # base math: M1_raw = 100 * 0.51 = 51.
        # final = (51 * 0.40) + (10 * 0.30) + (0 * 0.30) = 20.4 + 3.0 = 23.4.
        # 23.4 maps to Safe / ALLOW
        assert resp.final_score == 23.4
        assert resp.final_severity == "Safe"
        assert resp.recommended_action == "ALLOW"

    def test_scenario_e_private_ip_rule_0_cap(self, engine):
        # A private IP address triggering a high confidence RF attack signature
        # Should be capped at Medium / MONITOR because there is no reputation intelligence
        req = AnalyzeRequest(
            model1=Model1Input(prediction="Malicious", confidence=0.98),
            model2=Model2Input(anomaly_score=10.0),
            model3=Model3Input(
                abuse_score=0.0, vt_malicious=0, vt_total_engines=70,
                intel_score=0.0, intel_severity="Safe",
                country="US", is_proxy=False, blacklisted=False
            ),
            source_ip="192.168.1.50"
        )
        resp = engine.analyze(req)
        assert resp.final_severity == "Medium"
        assert resp.recommended_action == "MONITOR"
        assert resp.final_score == 55.0
        assert "capped at medium/monitor for private internal ip" in " ".join(resp.explanation).lower()

    def test_scenario_f_standalone_reputation(self, engine):
        req = AnalyzeRequest(
            model1=Model1Input(prediction="Normal", confidence=0.98),
            model2=Model2Input(anomaly_score=10.0),
            model3=Model3Input(
                abuse_score=0.0, vt_malicious=0, vt_total_engines=70,
                intel_score=92.0, intel_severity="Malicious",
                country="US", is_proxy=False, blacklisted=False
            ),
            source_ip="1.2.3.4"
        )
        resp = engine.analyze(req)
        assert resp.final_severity == "Medium"
        assert resp.recommended_action == "MONITOR"
        assert resp.final_score == 65.0
        assert "standalone severe reputation risk detected" in " ".join(resp.explanation).lower()

    def test_scenario_blacklist_low_signal_no_override(self, engine):
        # 1/91 VT malicious is below the threshold of 5, should NOT trigger override
        req = AnalyzeRequest(
            model1=Model1Input(prediction="Normal", confidence=0.98),
            model2=Model2Input(anomaly_score=10.0),
            model3=Model3Input(
                abuse_score=10.0, vt_malicious=1, vt_total_engines=91,
                intel_score=5.0, intel_severity="Safe",
                country="US", is_proxy=False, blacklisted=False
            ),
            source_ip="1.2.3.4"
        )
        resp = engine.analyze(req)
        assert resp.final_severity != "Critical"
        assert resp.recommended_action != "BLOCK"

    def test_scenario_blacklist_high_signal_override(self, engine):
        # 6/91 VT malicious is at/above the threshold of 5, should trigger override
        req = AnalyzeRequest(
            model1=Model1Input(prediction="Normal", confidence=0.98),
            model2=Model2Input(anomaly_score=10.0),
            model3=Model3Input(
                abuse_score=10.0, vt_malicious=6, vt_total_engines=91,
                intel_score=30.0, intel_severity="Suspicious",
                country="US", is_proxy=False, blacklisted=False
            ),
            source_ip="1.2.3.4"
        )
        resp = engine.analyze(req)
        assert resp.final_severity == "Critical"
        assert resp.recommended_action == "BLOCK"
        assert resp.final_score == 95.0
        assert "IP present in threat intelligence blacklists" in " ".join(resp.explanation)


class TestUnifiedAnalyzeIntegration:
    def test_unified_analyze_success(self, client):
        from unittest.mock import patch
        from datetime import datetime, timezone
        from app.schemas.intelligence import (
            IntelligenceResponse, VirusTotalIntelResult, AbuseIpDbIntelResult, GeoIpIntelResult
        )
        
        mock_intel = IntelligenceResponse(
            ip="8.8.8.8",
            status="completed",
            intel_score=0,
            severity="Safe",
            virustotal=VirusTotalIntelResult(status="completed", malicious=0, suspicious=0, harmless=70, undetected=0, total_engines=70),
            abuseipdb=AbuseIpDbIntelResult(status="completed", abuse_confidence_score=0, total_reports=0, is_whitelisted=False, is_tor=False),
            geoip=GeoIpIntelResult(status="completed", country="US", is_proxy=False, is_hosting=False),
            message="Clean IP",
            looked_up_at=datetime.now(timezone.utc)
        )
        
        with patch("app.api.analyze_routes._model_rf.predict") as mock_rf, \
             patch("app.api.analyze_routes._model_if.predict_raw") as mock_if, \
             patch("app.services.intelligence.enrichment.IntelligenceEnrichmentService.enrich") as mock_enrich:
             
            mock_rf.return_value = {"prediction_code": 0, "classification": "Normal", "confidence_scores": {"Normal": 0.98, "Suspicious": 0.01, "Malicious": 0.01}}
            mock_if.return_value = {"anomaly_score": 0.45, "is_anomaly": False, "normalized_score": 10.0}
            mock_enrich.return_value = mock_intel
            
            body = {
                "ip": "8.8.8.8",
                "flow_features": {
                    "flow_duration": 0.1,
                    "src_pkts": 2,
                    "dst_pkts": 2,
                    "src_bytes": 128,
                    "dst_bytes": 128,
                    "pkt_len_mean": 64.0,
                    "pkt_len_std": 0.0,
                    "iat_mean": 0.05,
                    "iat_std": 0.0,
                    "src_port": 53,
                    "protocol": "UDP"
                }
            }
            
            r = client.post("/api/v1/analyze", json=body)
            assert r.status_code == 200
            data = r.json()
            assert data["ip"] == "8.8.8.8"
            assert data["final_score"] <= 25.0
            assert data["severity"] in ("SAFE", "NORMAL", "LOW")
            assert data["action"] == "ALLOW"
            assert data["degraded_mode"] is False
            assert "trace_id" in data
            assert "latency_ms" in data

    def test_unified_analyze_degraded_mode(self, client):
        from unittest.mock import patch
        
        with patch("app.api.analyze_routes._model_rf.predict") as mock_rf, \
             patch("app.api.analyze_routes._model_if.predict_raw") as mock_if, \
             patch("app.services.intelligence.enrichment.IntelligenceEnrichmentService.enrich") as mock_enrich:
             
            mock_rf.return_value = {"prediction_code": 0, "classification": "Normal", "confidence_scores": {"Normal": 0.98, "Suspicious": 0.01, "Malicious": 0.01}}
            mock_if.return_value = {"anomaly_score": 0.45, "is_anomaly": False, "normalized_score": 10.0}
            # Simulate threat intel failure
            mock_enrich.side_effect = Exception("API connection timed out")
            
            body = {
                "ip": "8.8.8.8",
                "flow_features": {
                    "flow_duration": 0.1,
                    "src_pkts": 2,
                    "dst_pkts": 2,
                    "src_bytes": 128,
                    "dst_bytes": 128,
                    "pkt_len_mean": 64.0,
                    "pkt_len_std": 0.0,
                    "iat_mean": 0.05,
                    "iat_std": 0.0,
                    "src_port": 53,
                    "protocol": "UDP"
                }
            }
            
            r = client.post("/api/v1/analyze", json=body)
            assert r.status_code == 200
            data = r.json()
            assert data["ip"] == "8.8.8.8"
            # Threat Intel should fall back to 0.0 rather than adding 28 risk points
            # RF = 1% malicious (confidence 0.01) -> score = 1.0
            # IF = normalized 10.0
            # Intel = None -> 0.0
            # w1 = 4/7 = 0.571, w2 = 3/7 = 0.429
            # final = 1 * 0.571 + 10 * 0.429 = 0.571 + 4.29 = 4.86.
            # Severity Safe / ALLOW
            assert data["final_score"] <= 10.0
            # When degraded, severity is DEGRADED if original was SAFE/NORMAL
            assert data["severity"] in ("SAFE", "NORMAL", "LOW", "DEGRADED")
            assert data["action"] == "ALLOW"
            assert data["degraded_mode"] is True
            assert "trace_id" in data
            assert "latency_ms" in data