import requests
import json
import time

BASE_URL = "http://127.0.0.1:8000/api/v1"

def print_step(step):
    print(f"\n[{step}]")
    print("-" * 40)

def main():
    print("=== CYBERSENTINEL E2E VERIFICATION SUITE ===")
    
    # 1. Inject Port Scan
    print_step("1. Injecting Port Scan (Demo Mode)")
    resp = requests.post(f"{BASE_URL}/demo/load?scenario=port_scan")
    if resp.status_code != 200:
        print("FAILED: Could not inject demo.")
        return
    
    demo_data = resp.json()
    alert_id = demo_data.get("alert_id")
    print(f"SUCCESS: Injected Port Scan. Alert ID: {alert_id}")
    
    time.sleep(2) # Wait for Supabase propagation

    # 2. Check Investigation Timeline
    print_step("2. Verifying Investigation Timeline")
    resp = requests.get(f"{BASE_URL}/alerts/{alert_id}/timeline")
    if resp.status_code == 200:
        events = resp.json()
        print(f"SUCCESS: Retrieved {len(events)} events in timeline.")
        for e in events:
            print(f"  - {e['timestamp']} | {e['event']}")
    else:
        print(f"FAILED: Timeline returned {resp.status_code}")

    # 3. Check AI Analyst: Show active threats
    print_step("3. Verifying AI Analyst: Show active threats")
    payload = {"message": "Show active threats", "session_id": "e2e_test_session"}
    resp = requests.post(f"{BASE_URL}/copilot/chat", json=payload)
    if resp.status_code == 200:
        chat = resp.json()
        print("SUCCESS: AI Analyst responded.")
        print("Intent:", chat.get("intent"))
        print("Response Snippet:\n", chat.get("response")[:300], "...\n")
        
        # Verify if Alert ID is in the response text
        if alert_id in chat.get("response", ""):
            print("=> VERIFIED: AI Analyst actually returned the injected Alert ID.")
        else:
            print("=> WARNING: AI Analyst did not mention the specific Alert ID. It might be returning generic text or summarizing.")
    else:
        print(f"FAILED: AI Analyst returned {resp.status_code}")

    # 4. Check AI Analyst: Explain latest alert
    print_step("4. Verifying AI Analyst: Explain latest alert")
    payload = {"message": f"Why was alert {alert_id} flagged?", "session_id": "e2e_test_session"}
    resp = requests.post(f"{BASE_URL}/copilot/chat", json=payload)
    if resp.status_code == 200:
        chat = resp.json()
        print("SUCCESS: AI Analyst responded.")
        print("Intent:", chat.get("intent"))
        print("Response Snippet:\n", chat.get("response")[:300], "...\n")
    else:
        print(f"FAILED: AI Analyst returned {resp.status_code}")

    # 5. Verify Reporting Consistency
    print_step("5. Verifying Reporting Consistency")
    # Check total alerts vs critical threats
    alerts_resp = requests.get(f"{BASE_URL}/threats")
    stats_resp = requests.get(f"{BASE_URL}/dashboard/stats")
    
    if alerts_resp.status_code == 200 and stats_resp.status_code == 200:
        alerts = alerts_resp.json()
        if "items" in alerts:
            alerts_count = len(alerts["items"])
        elif isinstance(alerts, list):
            alerts_count = len(alerts)
        else:
            alerts_count = 0
            
        stats = stats_resp.json()
        dashboard_active = stats.get("active_threats_count", 0)
        
        print(f"Alerts Endpoint returns: {alerts_count} total alerts on page 1")
        print(f"Dashboard Stats returns: {dashboard_active} active threats (overall)")
        print("SUCCESS: Both endpoints are online and reporting data.")
    else:
        print("FAILED: Could not retrieve reporting stats.")

    print("\n=== VERIFICATION COMPLETE ===")

if __name__ == "__main__":
    main()
