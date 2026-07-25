# CyberSentinel Deployment Guide

This guide details the exact steps required to deploy the CyberSentinel API and Dashboard from scratch. It serves as evidence of system reproducibility for the FYP defense.

## Prerequisites
- Python 3.12+ (for Backend API)
- Node.js 18+ (for Frontend Dashboard)
- Supabase Account (for PostgreSQL & Real-time)
- API Keys: Groq (LLM), VirusTotal, AbuseIPDB

## Step 1: Clone and Configure Backend

```bash
# 1. Clone repository
git clone https://github.com/your-username/cybersentinel_api.git
cd cybersentinel_api

# 2. Setup Virtual Environment
python3 -m venv venv
source venv/bin/activate

# 3. Install Dependencies
pip install -r requirements.txt

# 4. Environment Variables
# Copy the example env file and insert your keys
cp .env.example .env
```

Ensure `.env` contains:
```env
SUPABASE_URL=https://[YOUR_PROJECT_ID].supabase.co
SUPABASE_SERVICE_ROLE_KEY=[YOUR_SERVICE_KEY]
GROQ_API_KEY=[YOUR_GROQ_KEY]
VIRUSTOTAL_API_KEY=[YOUR_VT_KEY]
ABUSEIPDB_API_KEY=[YOUR_ABUSEIPDB_KEY]
```

## Step 2: Database Setup

CyberSentinel uses Supabase for database management.

1. Navigate to your Supabase SQL Editor.
2. Run the core schema setup script located at `scripts/schema.sql`.
3. Run the ML baseline seeding script located at `scripts/seed_baselines.sql`.
4. Ensure Row Level Security (RLS) is configured according to the backend service role constraints.

## Step 3: Start the CyberSentinel Engine

Run the following command to start the FastAPI backend, initialize the Packet Capture thread, and open the WebSocket Hub:

```bash
# Must be run with elevated privileges if capturing live interfaces (e.g., sudo)
# For local dev/testing, standard privileges work if using synthetic packet injection.
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Verify backend health by navigating to: `http://127.0.0.1:8000/api/v1/docs`

## Step 4: Clone and Configure Frontend Dashboard

```bash
# 1. Navigate to frontend directory
cd ../cybersentinel

# 2. Install Node Dependencies
npm install

# 3. Environment Variables
cp .env.local.example .env.local
```

Ensure `.env.local` contains:
```env
NEXT_PUBLIC_API_URL=http://127.0.0.1:8000/api/v1
NEXT_PUBLIC_WS_URL=ws://127.0.0.1:8000/ws
```

## Step 5: Start the Dashboard

```bash
npm run dev
```

Navigate to `http://localhost:3000` to access the CyberSentinel SOC Dashboard.

## Troubleshooting

- **Packet Capture Not Starting:** Ensure you are running Python with the appropriate network interface permissions. On macOS/Linux, `sudo` might be required for raw sockets.
- **WebSocket Disconnects:** Check that the backend Uvicorn server is running and the `.env.local` WS URL matches the backend port.
- **LLM Analyst Failing:** Verify your Groq API key has sufficient quota and is correctly loaded in the `.env` file.
