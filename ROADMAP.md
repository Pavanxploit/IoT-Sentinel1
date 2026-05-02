# IoT Sentinel Roadmap

This roadmap turns IoT Sentinel from a strong portfolio project into a job-ready security product demo.

## Current Status

| Area | Status | Notes |
| --- | --- | --- |
| Repo hygiene | Done | `.next`, `node_modules`, and `.env` are ignored. |
| App structure | Done | Next.js App Router with dashboard and API routes. |
| Auth | Done | Email/password login with signed HTTP-only cookies. |
| Device identity | Done | Per-device ingest tokens. |
| Threat detection | Done | Score, verdict, category, confidence, signals, and action. |
| Response | Done | Alerts and IP blocklist enforcement. |
| Attack simulation | Done | Attack Lab scenarios use the same detection pipeline. |
| README | Done | Architecture, detection matrix, setup, deploy, and API examples. |
| Deployment | Next | Add live Vercel URL after environment variables are configured. |

## Phase 1: Make It Demo-Ready

Goal: anyone opening the repo should understand and try the project in under 2 minutes.

- Deploy on Vercel.
- Add live demo URL to `README.md`.
- Create one demo account/project/device in the deployed app.
- Run one Attack Lab scenario and capture dashboard screenshots.
- Replace the SVG placeholder screenshot with real app screenshots.
- Verify `/api/health` returns `ok: true`.

Success condition:

- GitHub README has a live link, screenshots, and clear demo flow.
- Vercel deployment works without local setup.

## Phase 2: Make Security Depth Obvious

Goal: show interviewer-level security thinking.

- Add per-project risk threshold settings.
- Add device token rotation.
- Add audit logs for block/unblock, alert resolve, and simulation run.
- Add detection tests for each attack scenario.
- Add rate-limit detection based on event count per IP/device window.
- Add a security explanation page for each event: why it scored that way.

Success condition:

- A reviewer can point to exact code for detection, response, and auditability.

## Phase 3: Make It Production-Shaped

Goal: make it look like a small SaaS security product.

- Add project invitations and roles: owner, analyst, viewer.
- Add CSV export for events and blocked IPs.
- Add alert notifications through email or Slack.
- Add device status heartbeat endpoint.
- Add Vercel Firewall or WAF documentation for pre-function IP blocking.
- Add seed script for demo data.

Success condition:

- The app feels useful for a small team monitoring IoT devices.

## Phase 4: Make It Portfolio/Interview Ready

Goal: package the project so it helps you get interviews.

- Add a 90-second demo video.
- Pin the repo on GitHub.
- Add this project to your resume under Security Projects.
- Write a short case study:
  - Problem
  - Threat model
  - Architecture
  - Detection logic
  - Response workflow
  - What you would improve next

Resume bullet examples:

- Built an IoT threat detection dashboard with authenticated device ingestion, rule-based scoring, alerting, and IP blocklist enforcement using Next.js and Postgres.
- Implemented attack simulations for Mirai-style brute force, port scanning, MQTT replay/flood, command injection, and data exfiltration to validate detection workflows.
- Designed project-scoped access control and per-device ingest tokens for secure multi-project IoT monitoring.

## What To Do Next

1. Deploy to Vercel with `DATABASE_URL` and `AUTH_SECRET`.
2. Add the live deployment URL to `README.md`.
3. Add real screenshots from the deployed dashboard.
4. Add tests for the detection engine.
5. Add token rotation and audit logs.

## Money Path

This can become a useful paid product only after the demo proves real value. The path is:

1. Portfolio project: get interviews and freelance conversations.
2. Demo product: show small IoT labs, colleges, or makerspaces.
3. Pilot product: monitor a small number of devices for one real user.
4. Paid product: add alerts, reports, roles, audit logs, and managed deployment.

Do not sell it as a finished security platform yet. Sell it as an IoT security monitoring prototype or MVP until it has real users, real alerts, and production hardening.
