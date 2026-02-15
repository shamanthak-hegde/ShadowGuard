# ShadowGuard

**Healthcare Shadow AI Detection & Governance System** | TreeHacks 2026

ShadowGuard intercepts HTTPS traffic to AI services (ChatGPT, Claude, Gemini), detects Protected Health Information (PHI) using NLP, redacts it in real-time, and provides a cybersecurity-themed governance dashboard with live WebSocket updates and automated voice alerts.

---

## Architecture

```
                    ┌──────────────┐
  Browser/App ───►  │  mitmproxy   │ ──► AI Service (OpenAI, Anthropic, Google)
                    │  + addon     │
                    └──────┬───────┘
                           │ POST /api/events
                    ┌──────▼───────┐
                    │   FastAPI    │ ──► VAPI Voice Calls (high-risk alerts)
                    │   Backend    │
                    └──────┬───────┘
                           │ WebSocket + REST
                    ┌──────▼───────┐
                    │    React     │
                    │  Dashboard   │
                    └──────────────┘
```

| Component | Stack | Port |
|-----------|-------|------|
| Proxy | mitmproxy + Python addon | 8080 |
| Backend | FastAPI, PostgreSQL 14, psycopg2 | 8000 |
| Dashboard | React 18, Vite, D3.js, TailwindCSS | 3000 |
| Voice Alerts | VAPI + GPT-5.2 + ElevenLabs | - |

---

## Quick Start

### 1. Start the backend + dashboard + database

```bash
docker compose up --build
```

This starts PostgreSQL, the FastAPI backend, and the React dashboard.

### 2. Seed demo data

```bash
curl -X POST http://localhost:8000/api/seed
```

### 3. Open the dashboard

Navigate to [http://localhost:3000](http://localhost:3000)

### 4. Start the proxy (separate terminal)

```bash
# Activate the conda environment
source /path/to/anaconda3/etc/profile.d/conda.sh && conda activate shadow

# Run mitmproxy with the ShadowGuard addon
mitmproxy -s shadowguard_addon.py
```

### 5. Route traffic through the proxy

```bash
export HTTPS_PROXY=http://localhost:8080
export HTTP_PROXY=http://localhost:8080
export SSL_CERT_FILE=~/.mitmproxy/mitmproxy-ca-cert.pem
```

Or launch a proxied Chrome:

```bash
# macOS
open -na "Google Chrome" --args \
  --proxy-server="http://localhost:8080" \
  --user-data-dir="/tmp/chrome-proxy-test"
```

---

## VAPI Voice Alerts

When a high-risk PHI exposure is detected (severity critical/high, risk score >= 70), ShadowGuard can automatically call the responsible staff via VAPI to notify them.

### Setup

1. Create a VAPI account at [vapi.ai](https://vapi.ai)
2. Configure a phone number and an assistant on the VAPI dashboard
3. The assistant should use template variables: `{{service}}`, `{{phi_types}}`, `{{risk_score}}`, `{{action_taken}}`, `{{timestamp}}`, `{{department}}`
4. Add your credentials to `.env`:

```env
VAPI_ENABLED=true
VAPI_API_KEY=your-private-key
VAPI_PHONE_NUMBER_ID=your-vapi-phone-id
VAPI_ASSISTANT_ID=your-assistant-id
ALERT_PHONE_NUMBER=+1XXXXXXXXXX
CALL_COOLDOWN_SECONDS=300
```

### How it works

- Calls are **only triggered** when `VAPI_ENABLED=true` — safe to run without it
- Seeding demo data does **not** trigger real calls (only inserts fake call records)
- Per-IP cooldown prevents call spam (default: 5 minutes)
- Test a call manually: `curl -X POST http://localhost:8000/api/calls/test`

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | Yes (Docker sets it) | `postgresql://shadowguard:shadowguard@localhost:5432/shadowguard` | PostgreSQL connection string |
| `VAPI_ENABLED` | No | `false` | Enable voice call alerts |
| `VAPI_API_KEY` | For calls | - | VAPI private API key |
| `VAPI_PHONE_NUMBER_ID` | For calls | - | VAPI phone number ID |
| `VAPI_ASSISTANT_ID` | For calls | - | Pre-configured VAPI assistant ID |
| `ALERT_PHONE_NUMBER` | For calls | - | Phone number to receive alert calls |
| `CALL_COOLDOWN_SECONDS` | No | `300` | Minimum seconds between calls per source IP |

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health` | Health check |
| `POST` | `/api/events` | Ingest event from mitmproxy |
| `GET` | `/api/events` | List events (supports `limit`, `offset`, `severity`, `service`, `status`) |
| `GET` | `/api/events/:id` | Get single event |
| `PATCH` | `/api/events/:id/status` | Update event status (active/mitigated/resolved) |
| `GET` | `/api/stats` | Dashboard aggregate statistics |
| `POST` | `/api/seed` | Seed database with demo data |
| `GET` | `/api/calls` | List VAPI call records |
| `GET` | `/api/calls/stats` | Voice call aggregate stats |
| `POST` | `/api/calls/test` | Trigger a test VAPI call |
| `WS` | `/api/ws` | WebSocket for real-time updates |

---

## Testing Interception

### Terminal test (with proxy running)

```bash
# Clean request (no PHI) — should be logged
curl -X POST https://api.openai.com/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sk-fake-test-key" \
  -d '{"model": "gpt-4", "messages": [{"role": "user", "content": "How do I sort a list in Python?"}]}'

# PHI request — should be detected and redacted
curl -X POST https://api.openai.com/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sk-fake-test-key" \
  -d '{"model": "gpt-4", "messages": [{"role": "user", "content": "Summarize notes for patient John Doe, SSN: 423-91-8847, DOB: 03/15/1958. Diagnosis E11.9 Type 2 Diabetes."}]}'
```

### Browser test

1. Launch Chrome with proxy: `--proxy-server="http://localhost:8080"`
2. Navigate to `http://mitm.it` and install the mitmproxy CA certificate
3. Go to `https://chatgpt.com` and type a message
4. Watch the dashboard update in real-time

---

## Project Structure

```
ShadowGuard/
├── shadowguard_addon.py    # mitmproxy addon — intercepts, detects PHI, posts to backend
├── phi_redactor.py         # PHI detection engine (Presidio + regex fallback)
├── docker-compose.yml      # PostgreSQL + backend + dashboard
├── .env                    # VAPI and other environment variables
├── backend/
│   ├── main.py             # FastAPI app, routes, WebSocket manager
│   ├── database.py         # PostgreSQL connection pool, table creation
│   ├── models.py           # Pydantic request/response models
│   ├── seed.py             # Demo data generator
│   ├── vapi_caller.py      # VAPI voice call integration
│   ├── requirements.txt    # Python dependencies
│   └── Dockerfile
└── dashboard/
    ├── src/
    │   ├── App.jsx         # Main app with state management + WebSocket
    │   ├── components/
    │   │   ├── StatsCards.jsx       # Summary stat cards
    │   │   ├── ThreatFeed.jsx       # Live threat feed sidebar
    │   │   ├── TrafficTimeline.jsx  # D3 traffic timeline chart
    │   │   ├── RiskHeatmap.jsx      # D3 risk heatmap
    │   │   ├── NetworkGraph.jsx     # D3 force-directed network graph
    │   │   ├── AuditLog.jsx         # Sortable/paginated audit table
    │   │   └── RedactionViewer.jsx  # Side-by-side original/redacted modal
    │   ├── hooks/
    │   │   └── useWebSocket.js      # WebSocket hook with auto-reconnect
    │   └── lib/
    │       └── api.js               # REST API client functions
    ├── package.json
    └── Dockerfile
```

---

## Troubleshooting

**"SSL certificate verify failed"**
Install/trust the mitmproxy CA cert: `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/.mitmproxy/mitmproxy-ca-cert.pem`

**"Connection refused" on port 8000**
Make sure `docker compose up` is running and the backend container is healthy.

**VAPI calls failing with 403**
Ensure `User-Agent` header is set (already handled in code). Check your VAPI API key is the **private** key, not the public one.

**VAPI calls failing with SSL errors**
The backend Docker container disables SSL verification for outbound VAPI calls to avoid certificate issues with proxies.

**Dashboard not updating**
Check the WebSocket connection indicator in the header. The dashboard auto-reconnects if the connection drops.
