# CyberSentinel API

CyberSentinel API is the local FastAPI analysis backend for CyberSentinel. It
provides authenticated packet capture, bounded flow-level analysis, WebSocket
events, AI Analyst context, Virus Scanner integrations, Threat Intelligence,
and Threat Response operations.

## Presentation architecture

### macOS

```text
Flutter native application
→ managed local FastAPI sidecar
→ TShark/dumpcap packet capture
→ Model 1 + Model 2 + Model 3 + Decision Engine
```

### Windows

```text
Flutter Web in Chrome
→ local FastAPI process
→ Wireshark/TShark with Npcap packet capture
→ flow analysis and WebSocket updates
```

Capture starts with an ephemeral in-memory session ID. It does not require a
workspace or a durable `capture_sessions` row.

The SQL files under `scripts/` are future migration assets only:

- `scripts/migrate_capture_sessions.sql`
- `scripts/rollback_capture_sessions.sql`

They are unapplied, not required by the presentation build, and must not be
executed without a coordinated compatible deployment and schema review.

## Requirements

- Python 3.12
- TShark and dumpcap
- macOS: Wireshark plus BPF capture permissions
- Windows: Wireshark/TShark and Npcap
- A Supabase project configured for the existing authenticated user/RLS model

## Environment

Copy the template:

```bash
cp .env.example .env
```

Configure these environment-variable names locally:

- `SUPABASE_URL`
- `SUPABASE_ANON_KEY`
- `SUPABASE_JWT_SECRET`
- `GROQ_API_KEY`
- `VIRUSTOTAL_API_KEY`
- `ABUSEIPDB_API_KEY`

Never commit `.env`, service-role keys, JWTs, local sidecar tokens, certificates,
packet captures, uploaded files, or scan artifacts.

## Setup

### macOS or Linux shell

```bash
python3.12 -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### Windows PowerShell

```powershell
py -3.12 -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Capture dependencies

### macOS

Install Wireshark with TShark and dumpcap, then ensure dumpcap can enumerate and
capture from the intended interface:

```bash
dumpcap -D
dumpcap -i en0 -c 5
```

Use Wireshark's supported BPF permission setup. Do not run the application as
root.

### Windows

Install Wireshark with TShark and Npcap. Enable the Npcap option appropriate for
your local account and verify interfaces with:

```powershell
tshark -D
```

## Run FastAPI

```bash
source venv/bin/activate
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

For Windows PowerShell:

```powershell
.\venv\Scripts\Activate.ps1
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

The managed macOS Flutter build starts this backend automatically using the
paths supplied in its local `config/dev.json`.

## Tests

Run all backend tests:

```bash
python -m pytest -q
```

Focused presentation validation:

```bash
python -m pytest \
  tests/test_capture_start_contract.py \
  tests/test_capture_live_consumer.py \
  tests/test_analysis_backpressure.py \
  tests/test_model2_real_artifact.py \
  tests/test_analyze_degradation_contract.py \
  tests/test_copilot_chat.py \
  tests/test_local_scanner.py \
  tests/test_settings_integrations.py -v
```

Startup smoke test:

```bash
python -c "from app.main import app; print(app.title)"
```

## Runtime guarantees

- Analysis uses a bounded queue and a small worker pool.
- Raw packet events do not wait for ML or database writes.
- Packet and flow IDs remain stable across live and analyzed updates.
- Storage failures do not suppress live WebSocket results.
- Pending packets are terminalized when capture stops.
- Durable capture-session history is intentionally postponed.
