# ShadowGuard — Quick Test Guide

## What This Tests
You're testing if mitmproxy can intercept HTTPS requests to AI services
(ChatGPT, Claude, Gemini) from both browser AND terminal, inspect the
content, detect PHI, and block dangerous requests.

---

## Step-by-Step (5 minutes to test)

### Terminal 1: Start the proxy

```bash
# Install mitmproxy (one-time)
# macOS:
brew install mitmproxy
# Linux:
pip install mitmproxy

# Start the proxy with the ShadowGuard addon
mitmdump -s shadowguard_addon.py --listen-port 8080
```

This terminal will show live intercepts with color-coded risk scores.

---

### Terminal 2: Install the CA cert (one-time)

The first time you run mitmproxy, it generates a CA certificate at
`~/.mitmproxy/mitmproxy-ca-cert.pem`. You need to trust this cert.

**macOS:**
```bash
# Add to system keychain
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain \
  ~/.mitmproxy/mitmproxy-ca-cert.pem
```

**Linux:**
```bash
sudo cp ~/.mitmproxy/mitmproxy-ca-cert.pem \
  /usr/local/share/ca-certificates/mitmproxy.crt
sudo update-ca-certificates
```

---

### Terminal 2: Test with terminal requests

```bash
# Set proxy environment variables
export HTTPS_PROXY=http://localhost:8080
export HTTP_PROXY=http://localhost:8080
export SSL_CERT_FILE=~/.mitmproxy/mitmproxy-ca-cert.pem

# Test 1: Simple curl to OpenAI (should be LOGGED)
curl -X POST https://api.openai.com/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sk-fake-test-key" \
  -d '{
    "model": "gpt-4",
    "messages": [{"role": "user", "content": "How do I sort a list in Python?"}]
  }'

# Test 2: Curl with PHI (should be BLOCKED!)
curl -X POST https://api.openai.com/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sk-fake-test-key" \
  -d '{
    "model": "gpt-4",
    "messages": [{"role": "user", "content": "Summarize notes for patient John Doe, MRN: 847291, SSN: 423-91-8847, DOB: 03/15/1958. Diagnosis E11.9 Type 2 Diabetes. Prescribed Metformin 1000mg."}]
  }'

# Test 3: Run the full automated test suite
python3 test_interception.py --auto
```

---

### Browser test

Open a NEW Chrome window that uses the proxy:

**macOS:**
```bash
open -na "Google Chrome" --args \
  --proxy-server="http://localhost:8080" \
  --user-data-dir="/tmp/chrome-proxy-test"
```

**Linux:**
```bash
google-chrome \
  --proxy-server="http://localhost:8080" \
  --user-data-dir="/tmp/chrome-proxy-test"
```

Then:
1. Navigate to `http://mitm.it` and install the mitmproxy cert for your OS
2. Go to `https://chatgpt.com`
3. Type a message — watch Terminal 1 light up with the intercept!
4. Try pasting fake patient data — it should show PHI detection

---

## What You Should See

In Terminal 1 (mitmproxy), for each intercepted request:

```
======================================================================
🛡️  SHADOWGUARD INTERCEPT
======================================================================
  ⏰ Time:      14:23:07
  🌐 Service:   OpenAI API
  📡 Method:    POST /v1/chat/completions
  📦 Size:      342 chars
  🚨 Risk Score: 85/100

  🚨 PHI DETECTED:
     - SSN: 1 match(es)
     - MRN: 1 match(es)
     - Patient_Name: 1 match(es)
     - DOB: 1 match(es)

  📋 Breakdown:
     • Unauthorized AI service: OpenAI API (+15)
     • PHI detected [SSN]: 1 match(es) (+15)
     • PHI detected [MRN]: 1 match(es) (+15)
     • PHI detected [Patient_Name]: 1 match(es) (+15)
     • PHI detected [DOB]: 1 match(es) (+15)
     • Medical keywords: 5 found (+15)
     • Data submission method: POST (+5)

  🚫 ACTION: REQUEST BLOCKED
  → User redirected to Safe Zone
======================================================================
```

For the blocked request, the caller receives:
```json
{
  "error": {
    "message": "🛡️ ShadowGuard: Request BLOCKED — potential PHI detected...",
    "type": "shadowguard_phi_block",
    "risk_score": 85,
    "phi_types_detected": ["SSN", "MRN", "Patient_Name", "DOB"]
  }
}
```

---

## Troubleshooting

**"SSL certificate verify failed"**
→ You haven't installed/trusted the mitmproxy CA cert. Follow the cert step above.

**"Connection refused"**  
→ mitmproxy isn't running. Start it in Terminal 1.

**"curl works but Python doesn't"**
→ Some Python HTTP libs ignore env vars. Use `--auto` flag with the test script,
   or set `REQUESTS_CA_BUNDLE=~/.mitmproxy/mitmproxy-ca-cert.pem` too.

**Browser shows "Your connection is not private"**
→ Navigate to `http://mitm.it` first to install the cert in the browser.
   Or use the `--user-data-dir` flag to launch a fresh Chrome profile.

**ChatGPT uses WebSockets / streaming**
→ mitmproxy handles SSE streams fine. WebSocket support is also built-in.
   You might see multiple intercepts for a single chat message (that's normal).