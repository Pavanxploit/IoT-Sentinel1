# IoT Sentinel

Real-time IoT threat detection and response dashboard for small devices, edge projects, and security labs.

IoT Sentinel accepts logs and packet summaries from ESP32-class devices, scores each event, creates alerts, and blocks malicious source IPs for a project. The goal is to show practical security engineering: device identity, authenticated ingestion, detection logic, incident response, and deployment.

![IoT Sentinel dashboard](public/product-dashboard.svg)

## Why This Project Matters

IoT projects often collect telemetry but do not answer the security questions that matter:

- Which device sent the event?
- Was the traffic normal, suspicious, or malicious?
- What signal triggered the verdict?
- What should the operator do next?
- Should this source IP be blocked for the project?

IoT Sentinel turns raw IoT logs into a security workflow: ingest, detect, alert, block, and investigate.

## Core Features

- Authenticated dashboard with HTTP-only JWT session cookies
- Project-scoped access control so users only see their authorized IoT projects
- Device provisioning with per-device ingest tokens
- ESP32-friendly JSON ingest API at `POST /api/ingest`
- Threat scoring engine with verdict, category, confidence, signals, and response action
- Automatic IP blocklist enforcement for malicious sources
- Manual block/unblock workflow for operators
- Open alerts queue for high-risk detections
- Attack Lab to simulate Mirai telnet brute force, port scans, MQTT flood/replay, command injection, and data exfiltration
- Vercel-ready deployment with Neon/Postgres persistence

## Architecture

```mermaid
flowchart LR
  Device["ESP32 / IoT Device"] -->|JSON logs + packet summary| Ingest["/api/ingest"]
  Ingest --> Auth["Device Token Check"]
  Auth --> Detection["Detection Engine"]
  Detection --> Events["Events Table"]
  Detection --> Alerts["Alerts Queue"]
  Detection --> Blocklist["IP Blocklist"]
  Blocklist --> Enforce["Reject Blocked Sources"]
  Events --> Dashboard["Operator Dashboard"]
  Alerts --> Dashboard
  Dashboard --> Lab["Attack Lab Simulations"]
  Lab --> Detection
```

## Detection Engine

The scoring engine is intentionally visible in code so reviewers can see the security thinking, not just CRUD screens.

| Signal | Category | Response |
| --- | --- | --- |
| Telnet, default passwords, repeated auth failures | `credential_attack` | Rotate credentials and rate-limit auth paths |
| Mirai terms, `wget`, `/bin/sh`, BusyBox payloads | `malware_delivery` | Quarantine device and rotate token |
| SYN scan, Nmap, many unique ports | `reconnaissance` | Restrict exposed management ports |
| MQTT flood or replay attack | `iot_protocol_abuse` | Validate broker ACLs and block replay sources |
| Large packets or outbound byte volume | `data_exfiltration` | Pause outbound traffic and inspect destination |
| Already-blocked source IP | `blocked_source` | Reject request and keep incident evidence |

Each event stores:

- `score`
- `verdict`
- `category`
- `confidence`
- `signals`
- `recommended_action`

## Attack Lab

The dashboard includes controlled simulations that generate malicious telemetry through the same event storage, scoring, alerting, and blocklist pipeline:

- Mirai-style telnet brute force
- Reconnaissance port scan
- MQTT flood and replay
- Firmware command injection
- Suspicious outbound data transfer

This makes the project demoable even when no physical IoT hardware is connected.

## Tech Stack

- Next.js App Router
- TypeScript
- Tailwind CSS
- Neon Postgres through `@neondatabase/serverless`
- `jose` for signed sessions
- `bcryptjs` for password hashing
- `zod` for API validation
- Vercel for hosting

## API Example

```bash
curl -X POST https://your-domain.vercel.app/api/ingest \
  -H "content-type: application/json" \
  -H "x-project-id: prj_xxx" \
  -H "x-device-id: dev_xxx" \
  -H "authorization: Bearer <device-token>" \
  -d '{
    "eventType": "network",
    "severity": "critical",
    "message": "Mirai botnet pattern: failed password attempts over telnet using root:root and wget /bin/sh payload",
    "packet": {
      "protocol": "tcp",
      "destPort": 23,
      "bytes": 4096
    },
    "telemetry": {
      "authFailures": 140,
      "connectionAttempts": 160,
      "firmware": "1.0.0"
    }
  }'
```

Example response:

```json
{
  "accepted": true,
  "eventId": "evt_...",
  "verdict": "malicious",
  "score": 100,
  "blocked": true,
  "signals": [
    "Device reported critical severity",
    "Traffic touched sensitive port 23",
    "Telemetry reports repeated authentication failures"
  ]
}
```

## Local Setup

```bash
npm install
```

Create `.env.local`:

```bash
DATABASE_URL="postgresql://user:password@host/database?sslmode=require"
AUTH_SECRET="replace-with-a-long-random-secret"
```

Generate a strong local secret:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Initialize database tables:

```bash
npm run db:setup
```

Run locally:

```bash
npm run dev
```

Open `http://localhost:3000`, register an account, create a project, provision a device, and run an Attack Lab simulation.

## Deploy To Vercel

1. Push this repository to GitHub.
2. Create or connect a Neon Postgres database in Vercel.
3. Add these Vercel environment variables:
   - `DATABASE_URL`
   - `AUTH_SECRET`
4. Deploy the project.
5. Visit `/api/health` to confirm the database is connected.
6. Add the deployed URL here:

```text
Live Demo: https://your-project.vercel.app
```

## GitHub Push

```bash
git add .
git commit -m "Harden IoT Sentinel security workflow"
git push origin main
```

## Product Roadmap

- Email or Slack alerts for critical detections
- Project invitation workflow with roles
- Device token rotation UI
- Audit log for operator actions
- Per-project detection threshold settings
- Vercel Firewall or edge WAF integration for pre-function blocking
- ML anomaly scoring from historical device baselines

## Security Note

This project blocks IPs inside the application API. For production network-level blocking, pair it with Vercel Firewall, a WAF, or cloud network controls so malicious requests can be stopped before reaching the serverless function.
