import Link from "next/link";
import { ArrowLeft, Cpu, GitBranch, KeyRound, RadioTower, Rocket, ShieldCheck } from "lucide-react";

export default function DocsPage() {
  return (
    <main className="min-h-screen bg-[#f6f7f2] px-5 py-8 text-[#17201c]">
      <div className="mx-auto w-full max-w-5xl space-y-6">
        <Link className="inline-flex items-center gap-2 rounded-md border border-[#d8ded5] bg-white px-3 py-2 text-sm font-semibold text-[#52625b] transition hover:border-[#2f6f5f] hover:text-[#2f6f5f]" href="/">
          <ArrowLeft className="h-4 w-4" aria-hidden="true" />
          Dashboard
        </Link>

        <section className="rounded-md border border-[#d8ded5] bg-white p-6 shadow-sm">
          <div className="flex items-start gap-4">
            <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-md bg-[#17201c] text-[#a7e3cc]">
              <ShieldCheck className="h-5 w-5" aria-hidden="true" />
            </span>
            <div>
              <h1 className="text-3xl font-semibold">IoT Sentinel Build Guide</h1>
              <p className="mt-2 max-w-3xl text-sm leading-6 text-[#65736d]">
                This app accepts compact device logs and packet summaries, scores each event,
                blocks malicious IPs at the application layer, and restricts dashboards by project
                membership.
              </p>
            </div>
          </div>
        </section>

        <section className="grid gap-4 md:grid-cols-3">
          <div className="rounded-md border border-[#d8ded5] bg-white p-5">
            <KeyRound className="mb-4 h-5 w-5 text-[#b7791f]" aria-hidden="true" />
            <h2 className="font-semibold">1. Configure secrets</h2>
            <p className="mt-2 text-sm leading-6 text-[#65736d]">
              Add <code className="font-mono">DATABASE_URL</code> and{" "}
              <code className="font-mono">AUTH_SECRET</code> in local and Vercel environments.
            </p>
          </div>
          <div className="rounded-md border border-[#d8ded5] bg-white p-5">
            <Cpu className="mb-4 h-5 w-5 text-[#2f6f5f]" aria-hidden="true" />
            <h2 className="font-semibold">2. Provision devices</h2>
            <p className="mt-2 text-sm leading-6 text-[#65736d]">
              Create a project, add a device, then store the generated token on the IoT node.
            </p>
          </div>
          <div className="rounded-md border border-[#d8ded5] bg-white p-5">
            <Rocket className="mb-4 h-5 w-5 text-[#a33d3d]" aria-hidden="true" />
            <h2 className="font-semibold">3. Deploy</h2>
            <p className="mt-2 text-sm leading-6 text-[#65736d]">
              Push to GitHub, import the repo in Vercel, set env vars, and deploy.
            </p>
          </div>
        </section>

        <section className="rounded-md border border-[#d8ded5] bg-white p-6 shadow-sm">
          <h2 className="flex items-center gap-2 text-xl font-semibold">
            <RadioTower className="h-5 w-5 text-[#2f6f5f]" aria-hidden="true" />
            Ingest API
          </h2>
          <p className="mt-2 text-sm leading-6 text-[#65736d]">
            Send JSON to <code className="font-mono">POST /api/ingest</code>. Use headers for
            credentials so small devices do not need a browser session.
          </p>
          <pre className="mt-4 overflow-x-auto rounded-md bg-[#101816] p-4 text-sm leading-7 text-[#dce8e1]">
            <code>{`POST /api/ingest
x-project-id: prj_xxx
x-device-id: dev_xxx
authorization: Bearer <device-token>
content-type: application/json

{
  "eventType": "network",
  "severity": "high",
  "message": "failed password attempts over telnet",
  "packet": {
    "protocol": "tcp",
    "destPort": 23,
    "bytes": 2048
  },
  "telemetry": {
    "firmware": "1.0.0",
    "heapFree": 49152
  }
}`}</code>
          </pre>
        </section>

        <section className="rounded-md border border-[#d8ded5] bg-white p-6 shadow-sm">
          <h2 className="text-xl font-semibold">ESP32 Arduino Example</h2>
          <pre className="mt-4 overflow-x-auto rounded-md bg-[#101816] p-4 text-sm leading-7 text-[#dce8e1]">
            <code>{`#include <WiFi.h>
#include <HTTPClient.h>

const char* WIFI_SSID = "your-wifi";
const char* WIFI_PASS = "your-password";
const char* API_URL = "https://your-domain.vercel.app/api/ingest";
const char* PROJECT_ID = "prj_xxx";
const char* DEVICE_ID = "dev_xxx";
const char* DEVICE_TOKEN = "paste-token-here";

void setup() {
  Serial.begin(115200);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
  }
}

void loop() {
  if (WiFi.status() == WL_CONNECTED) {
    HTTPClient http;
    http.begin(API_URL);
    http.addHeader("content-type", "application/json");
    http.addHeader("x-project-id", PROJECT_ID);
    http.addHeader("x-device-id", DEVICE_ID);
    http.addHeader("authorization", String("Bearer ") + DEVICE_TOKEN);

    String body = "{";
    body += "\\"eventType\\":\\"network\\",";
    body += "\\"severity\\":\\"medium\\",";
    body += "\\"message\\":\\"periodic telemetry\\",";
    body += "\\"packet\\":{\\"protocol\\":\\"tcp\\",\\"destPort\\":443,\\"bytes\\":512},";
    body += "\\"telemetry\\":{\\"firmware\\":\\"1.0.0\\",\\"heapFree\\":" + String(ESP.getFreeHeap()) + "}";
    body += "}";

    int statusCode = http.POST(body);
    Serial.println(statusCode);
    Serial.println(http.getString());
    http.end();
  }

  delay(30000);
}`}</code>
          </pre>
        </section>

        <section className="rounded-md border border-[#d8ded5] bg-white p-6 shadow-sm">
          <h2 className="flex items-center gap-2 text-xl font-semibold">
            <GitBranch className="h-5 w-5 text-[#17201c]" aria-hidden="true" />
            GitHub and Vercel
          </h2>
          <pre className="mt-4 overflow-x-auto rounded-md bg-[#101816] p-4 text-sm leading-7 text-[#dce8e1]">
            <code>{`npm run build
git add .
git commit -m "Build IoT Sentinel MVP"
gh repo create iot-sentinel --private --source=. --remote=origin --push`}</code>
          </pre>
          <p className="mt-4 text-sm leading-6 text-[#65736d]">
            In Vercel, import the GitHub repo, add the environment variables, and deploy. For
            network-level blocking before the request reaches a Function, add Vercel Firewall rules
            or a WAF integration; this starter enforces blocks inside the ingest API.
          </p>
        </section>
      </div>
    </main>
  );
}
