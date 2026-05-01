# IoT Sentinel

IoT Sentinel is a Next.js control plane for IoT security telemetry. It accepts logs and packet summaries from devices, scores events as clean, suspicious, or malicious, isolates access by project membership, and blocks malicious source IPs inside the ingest API.

## Features

- Email/password login with signed HTTP-only session cookies
- Private projects with membership-based dashboard access
- Per-device ingest tokens for ESP32, gateways, sensors, cameras, and test nodes
- `POST /api/ingest` for JSON logs and packet summaries
- Heuristic risk scoring for malware terms, auth abuse, risky ports, scans, floods, and event rate
- Automatic and manual IP blocklist enforcement
- Vercel-ready Postgres persistence through Neon or any Postgres database

## Local Setup

Install dependencies:

```bash
npm install
```

Create `.env.local`:

```bash
DATABASE_URL="postgresql://..."
AUTH_SECRET="replace-with-a-long-random-secret"
```

Generate a local secret:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Initialize database tables:

```bash
npm run db:setup
```

Run the app:

```bash
npm run dev
```

Open `http://localhost:3000`, register an account, create a device, and copy the device token.

## Device Ingest

Send compact JSON to the ingest endpoint:

```bash
curl -X POST http://localhost:3000/api/ingest \
  -H "content-type: application/json" \
  -H "x-project-id: prj_xxx" \
  -H "x-device-id: dev_xxx" \
  -H "authorization: Bearer <device-token>" \
  -d '{"eventType":"network","severity":"high","message":"telnet brute force","packet":{"protocol":"tcp","destPort":23,"bytes":2048}}'
```

The API returns a verdict, score, event ID, and whether the source IP was blocked.

## GitHub

From this folder:

```bash
npm run build
git add .
git commit -m "Build IoT Sentinel MVP"
gh repo create iot-sentinel --private --source=. --remote=origin --push
```

If you prefer the GitHub website, create an empty repo, then run:

```bash
git remote add origin https://github.com/<your-user>/iot-sentinel.git
git push -u origin main
```

## Vercel Deployment

1. Push the repo to GitHub.
2. In Vercel, create or connect a Neon Postgres database and copy `DATABASE_URL`.
3. Import the GitHub repo in Vercel.
4. Add environment variables:
   - `DATABASE_URL`
   - `AUTH_SECRET`
5. Deploy.
6. Visit `/api/health` after deploy. The app creates tables automatically if needed.

## Production Notes

The app blocklist rejects requests inside the ingest API. For blocking before traffic reaches a Vercel Function, add Vercel Firewall rules, WAF rules, or an edge security provider. For real-world production, add email verification, project invitations, audit logs, token rotation UI, alerting, and a stronger ML or SIEM-backed detection pipeline.
