import Link from "next/link";
import { redirect } from "next/navigation";
import {
  Activity,
  Ban,
  Cpu,
  Gauge,
  KeyRound,
  LogOut,
  Plus,
  RadioTower,
  ShieldAlert,
  ShieldCheck,
  Siren,
} from "lucide-react";
import { getCurrentUser } from "@/lib/auth";
import { isDatabaseConfigured } from "@/lib/db";
import { asNumber, formatDate, formatNumber } from "@/lib/format";
import {
  getDashboard,
  listAttackScenarios,
  type DeviceSummary,
  type ProjectSummary,
  type SecurityAlert,
  type SecurityEvent,
} from "@/lib/repository";
import { SetupRequired } from "@/components/setup-required";

export const dynamic = "force-dynamic";

type SearchParams = Promise<Record<string, string | string[] | undefined>>;

function scoreClass(score: number) {
  if (score >= 75) {
    return "bg-[#fde2df] text-[#9f2d24] border-[#f3b9b1]";
  }
  if (score >= 45) {
    return "bg-[#fff1cf] text-[#8a5a00] border-[#f1d38a]";
  }
  return "bg-[#e3f6eb] text-[#236447] border-[#bfe7cf]";
}

function statusClass(status: string) {
  if (status === "online") {
    return "bg-[#e3f6eb] text-[#236447] border-[#bfe7cf]";
  }
  if (status === "idle") {
    return "bg-[#fff1cf] text-[#8a5a00] border-[#f1d38a]";
  }
  return "bg-white text-[#65736d] border-[#d8ded5]";
}

function verdictClass(verdict: string) {
  if (verdict === "malicious") {
    return "text-[#b8322a]";
  }
  if (verdict === "suspicious") {
    return "text-[#9a6500]";
  }
  return "text-[#236447]";
}

function MetricCard({
  icon: Icon,
  label,
  value,
  tone,
}: {
  icon: typeof Activity;
  label: string;
  value: string;
  tone: string;
}) {
  return (
    <div className="rounded-md border border-[#d8ded5] bg-white p-4 shadow-sm">
      <div className="flex items-center justify-between gap-3">
        <p className="text-sm font-medium text-[#65736d]">{label}</p>
        <Icon className={`h-5 w-5 ${tone}`} aria-hidden="true" />
      </div>
      <p className="mt-4 font-mono text-3xl font-semibold tracking-normal text-[#17201c]">{value}</p>
    </div>
  );
}

function ProjectList({ projects }: { projects: ProjectSummary[] }) {
  if (projects.length === 0) {
    return <p className="text-sm leading-6 text-[#65736d]">Create a project to start provisioning devices.</p>;
  }

  return (
    <div className="grid gap-3">
      {projects.map((project) => (
        <div key={project.id} className="rounded-md border border-[#d8ded5] bg-white p-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <p className="font-semibold text-[#17201c]">{project.name}</p>
              <p className="mt-1 text-sm text-[#65736d]">{project.description || "No description"}</p>
            </div>
            <span className="rounded-md border border-[#c9d8d0] bg-[#f6f7f2] px-2 py-1 text-xs font-semibold uppercase tracking-normal text-[#2f6f5f]">
              {project.member_role}
            </span>
          </div>
          <dl className="mt-4 grid grid-cols-3 gap-3 text-sm">
            <div>
              <dt className="text-[#65736d]">Devices</dt>
              <dd className="mt-1 font-mono font-semibold">{project.device_count}</dd>
            </div>
            <div>
              <dt className="text-[#65736d]">Events</dt>
              <dd className="mt-1 font-mono font-semibold">{project.event_count}</dd>
            </div>
            <div>
              <dt className="text-[#65736d]">Malicious</dt>
              <dd className="mt-1 font-mono font-semibold text-[#b8322a]">{project.malicious_count}</dd>
            </div>
          </dl>
          <p className="mt-3 text-xs text-[#65736d]">Last activity: {formatDate(project.last_activity)}</p>
        </div>
      ))}
    </div>
  );
}

function DeviceRows({ devices }: { devices: DeviceSummary[] }) {
  if (devices.length === 0) {
    return (
      <tr>
        <td className="px-4 py-6 text-sm text-[#65736d]" colSpan={5}>
          No devices yet. Add an ESP32, gateway, camera, sensor, or test node.
        </td>
      </tr>
    );
  }

  return devices.map((device) => (
    <tr key={device.id} className="border-t border-[#e5e8e2]">
      <td className="px-4 py-3">
        <p className="font-medium text-[#17201c]">{device.name}</p>
        <p className="font-mono text-xs text-[#65736d]">{device.id}</p>
      </td>
      <td className="px-4 py-3 text-sm text-[#52625b]">{device.project_name}</td>
      <td className="px-4 py-3 text-sm text-[#52625b]">{device.kind}</td>
      <td className="px-4 py-3">
        <span className={`rounded-md border px-2 py-1 text-xs font-semibold ${statusClass(device.live_status)}`}>
          {device.live_status}
        </span>
      </td>
      <td className="px-4 py-3 text-sm text-[#52625b]">{formatDate(device.last_seen_at)}</td>
    </tr>
  ));
}

function EventRows({ events }: { events: SecurityEvent[] }) {
  if (events.length === 0) {
    return (
      <tr>
        <td className="px-4 py-6 text-sm text-[#65736d]" colSpan={8}>
          Events will appear here after a device posts to <code className="font-mono">/api/ingest</code>.
        </td>
      </tr>
    );
  }

  return events.map((event) => (
    <tr key={event.id} className="border-t border-[#e5e8e2]">
      <td className="px-4 py-3">
        <p className={`font-semibold ${verdictClass(event.verdict)}`}>{event.verdict}</p>
        <p className="font-mono text-xs text-[#65736d]">{event.id}</p>
      </td>
      <td className="px-4 py-3">
        <span className={`rounded-md border px-2 py-1 font-mono text-xs font-semibold ${scoreClass(asNumber(event.score))}`}>
          {event.score}
        </span>
      </td>
      <td className="px-4 py-3 text-sm text-[#52625b]">{event.source_ip}</td>
      <td className="px-4 py-3 text-sm text-[#52625b]">{event.device_name ?? "Unknown"}</td>
      <td className="px-4 py-3">
        <p className="text-sm font-semibold text-[#17201c]">{event.category.replaceAll("_", " ")}</p>
        <p className="font-mono text-xs text-[#65736d]">{event.confidence}% confidence</p>
      </td>
      <td className="px-4 py-3 text-sm text-[#52625b]">{event.summary}</td>
      <td className="px-4 py-3 text-sm text-[#52625b]">{event.recommended_action}</td>
      <td className="px-4 py-3 text-sm text-[#52625b]">{formatDate(event.created_at)}</td>
    </tr>
  ));
}

function AlertList({ alerts }: { alerts: SecurityAlert[] }) {
  if (alerts.length === 0) {
    return <p className="text-sm text-[#65736d]">No open alerts.</p>;
  }

  return (
    <div className="grid gap-3">
      {alerts.map((alert) => (
        <div
          className="rounded-md border border-[#f3b9b1] bg-[#fff7f6] p-4"
          key={alert.id}
        >
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <p className="text-sm font-semibold uppercase tracking-normal text-[#9f2d24]">
                {alert.severity}
              </p>
              <h3 className="mt-1 font-semibold text-[#17201c]">{alert.title}</h3>
              <p className="mt-2 text-sm leading-6 text-[#65736d]">{alert.description}</p>
            </div>
            <form action="/api/alerts/resolve" method="post">
              <input name="alertId" type="hidden" value={alert.id} />
              <button
                className="rounded-md border border-[#d4b4af] bg-white px-3 py-2 text-sm font-semibold text-[#7a2d27] transition hover:border-[#9f2d24]"
                type="submit"
              >
                Resolve
              </button>
            </form>
          </div>
          <p className="mt-3 text-sm leading-6 text-[#52625b]">{alert.action}</p>
          <p className="mt-3 font-mono text-xs text-[#65736d]">
            {alert.source_ip ?? "unknown source"} | score {alert.score ?? 0} | {formatDate(alert.created_at)}
          </p>
        </div>
      ))}
    </div>
  );
}

export default async function Home({ searchParams }: { searchParams?: SearchParams }) {
  if (!isDatabaseConfigured()) {
    return <SetupRequired />;
  }

  const user = await getCurrentUser();

  if (!user) {
    redirect("/login");
  }

  const params = searchParams ? await searchParams : {};
  const welcome = params.welcome === "1";
  const simulationStatus = params.simulation;
  const data = await getDashboard(user.id);
  const attackScenarios = listAttackScenarios();

  return (
    <main className="min-h-screen bg-[#f6f7f2] text-[#17201c]">
      <header className="border-b border-[#d8ded5] bg-white">
        <div className="mx-auto flex w-full max-w-7xl flex-wrap items-center justify-between gap-4 px-5 py-4">
          <Link className="flex items-center gap-3" href="/">
            <span className="flex h-10 w-10 items-center justify-center rounded-md bg-[#17201c] text-[#a7e3cc]">
              <ShieldCheck className="h-5 w-5" aria-hidden="true" />
            </span>
            <span>
              <span className="block text-lg font-semibold">IoT Sentinel</span>
              <span className="block text-xs text-[#65736d]">Device security control plane</span>
            </span>
          </Link>
          <nav className="flex items-center gap-2">
            <Link
              className="inline-flex items-center gap-2 rounded-md border border-[#d8ded5] bg-white px-3 py-2 text-sm font-semibold text-[#52625b] transition hover:border-[#2f6f5f] hover:text-[#2f6f5f]"
              href="/docs"
            >
              <RadioTower className="h-4 w-4" aria-hidden="true" />
              API guide
            </Link>
            <form action="/api/auth/logout" method="post">
              <button
                className="inline-flex items-center gap-2 rounded-md bg-[#17201c] px-3 py-2 text-sm font-semibold text-white transition hover:bg-[#2d3a34]"
                type="submit"
              >
                <LogOut className="h-4 w-4" aria-hidden="true" />
                Sign out
              </button>
            </form>
          </nav>
        </div>
      </header>

      <div className="mx-auto grid w-full max-w-7xl gap-6 px-5 py-6">
        {welcome ? (
          <section className="rounded-md border border-[#bfe7cf] bg-[#e3f6eb] p-4 text-sm text-[#236447]">
            Your workspace is ready. Add a device to generate its ingest token, then send a test
            event to <code className="font-mono">/api/ingest</code>.
          </section>
        ) : null}

        <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-6">
          <MetricCard icon={ShieldCheck} label="Projects" value={formatNumber(data.stats.project_count)} tone="text-[#2f6f5f]" />
          <MetricCard icon={Cpu} label="Devices" value={formatNumber(data.stats.device_count)} tone="text-[#2f6f5f]" />
          <MetricCard icon={Activity} label="Events" value={formatNumber(data.stats.event_count)} tone="text-[#b7791f]" />
          <MetricCard icon={Siren} label="Malicious" value={formatNumber(data.stats.malicious_count)} tone="text-[#b8322a]" />
          <MetricCard icon={Ban} label="Blocked IPs" value={formatNumber(data.stats.blocked_count)} tone="text-[#a33d3d]" />
          <MetricCard icon={ShieldAlert} label="Open Alerts" value={formatNumber(data.stats.alert_count)} tone="text-[#a33d3d]" />
        </section>

        <section className="grid gap-6 xl:grid-cols-[0.9fr_1.1fr]">
          <div className="space-y-6">
            <section className="rounded-md border border-[#d8ded5] bg-white p-5 shadow-sm">
              <div className="mb-4 flex items-center justify-between gap-3">
                <div>
                  <h2 className="text-lg font-semibold">Projects</h2>
                  <p className="mt-1 text-sm text-[#65736d]">Access is scoped by project membership.</p>
                </div>
                <Gauge className="h-5 w-5 text-[#2f6f5f]" aria-hidden="true" />
              </div>
              <ProjectList projects={data.projects} />
            </section>

            <section className="rounded-md border border-[#d8ded5] bg-white p-5 shadow-sm">
              <h2 className="text-lg font-semibold">Create Project</h2>
              <form action="/api/projects" className="mt-4 grid gap-3" method="post">
                <input
                  className="rounded-md border border-[#cfd8d1] px-3 py-2 text-sm outline-none transition focus:border-[#2f6f5f] focus:ring-2 focus:ring-[#a7e3cc]"
                  name="name"
                  placeholder="Project name"
                  required
                />
                <textarea
                  className="min-h-24 rounded-md border border-[#cfd8d1] px-3 py-2 text-sm outline-none transition focus:border-[#2f6f5f] focus:ring-2 focus:ring-[#a7e3cc]"
                  name="description"
                  placeholder="Purpose, site, or customer"
                />
                <button
                  className="inline-flex w-fit items-center gap-2 rounded-md bg-[#2f6f5f] px-4 py-2 text-sm font-semibold text-white transition hover:bg-[#235a4d]"
                  type="submit"
                >
                  <Plus className="h-4 w-4" aria-hidden="true" />
                  Add project
                </button>
              </form>
            </section>

            <section className="rounded-md border border-[#d8ded5] bg-white p-5 shadow-sm">
              <h2 className="text-lg font-semibold">Provision Device</h2>
              <form action="/api/devices" className="mt-4 grid gap-3" method="post">
                <select
                  className="rounded-md border border-[#cfd8d1] px-3 py-2 text-sm outline-none transition focus:border-[#2f6f5f] focus:ring-2 focus:ring-[#a7e3cc]"
                  name="projectId"
                  required
                >
                  {data.projects.map((project) => (
                    <option key={project.id} value={project.id}>
                      {project.name}
                    </option>
                  ))}
                </select>
                <input
                  className="rounded-md border border-[#cfd8d1] px-3 py-2 text-sm outline-none transition focus:border-[#2f6f5f] focus:ring-2 focus:ring-[#a7e3cc]"
                  name="name"
                  placeholder="Device name"
                  required
                />
                <div className="grid gap-3 sm:grid-cols-3">
                  <input className="rounded-md border border-[#cfd8d1] px-3 py-2 text-sm outline-none transition focus:border-[#2f6f5f] focus:ring-2 focus:ring-[#a7e3cc]" name="kind" placeholder="ESP32" />
                  <input className="rounded-md border border-[#cfd8d1] px-3 py-2 text-sm outline-none transition focus:border-[#2f6f5f] focus:ring-2 focus:ring-[#a7e3cc]" name="location" placeholder="Lab A" />
                  <input className="rounded-md border border-[#cfd8d1] px-3 py-2 text-sm outline-none transition focus:border-[#2f6f5f] focus:ring-2 focus:ring-[#a7e3cc]" name="firmware" placeholder="v1.0.0" />
                </div>
                <button
                  className="inline-flex w-fit items-center gap-2 rounded-md bg-[#17201c] px-4 py-2 text-sm font-semibold text-white transition hover:bg-[#2d3a34]"
                  disabled={data.projects.length === 0}
                  type="submit"
                >
                  <KeyRound className="h-4 w-4" aria-hidden="true" />
                  Generate device token
                </button>
              </form>
            </section>

            <section id="attack-lab" className="rounded-md border border-[#d8ded5] bg-white p-5 shadow-sm">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <h2 className="text-lg font-semibold">Attack Lab</h2>
                  <p className="mt-1 text-sm text-[#65736d]">Generate controlled malicious telemetry for a device.</p>
                </div>
                <Siren className="h-5 w-5 text-[#b8322a]" aria-hidden="true" />
              </div>

              {simulationStatus === "created" ? (
                <p className="mt-4 rounded-md border border-[#bfe7cf] bg-[#e3f6eb] px-3 py-2 text-sm text-[#236447]">
                  Simulation created. Review the new event, alert, and blocklist entry.
                </p>
              ) : null}
              {simulationStatus === "failed" ? (
                <p className="mt-4 rounded-md border border-[#f3b9b1] bg-[#fde2df] px-3 py-2 text-sm text-[#9f2d24]">
                  Simulation failed. Choose a device that belongs to the selected project.
                </p>
              ) : null}

              <form action="/api/simulations" className="mt-4 grid gap-3" method="post">
                <select
                  className="rounded-md border border-[#cfd8d1] px-3 py-2 text-sm outline-none transition focus:border-[#2f6f5f] focus:ring-2 focus:ring-[#a7e3cc]"
                  name="projectId"
                  required
                >
                  {data.projects.map((project) => (
                    <option key={project.id} value={project.id}>
                      {project.name}
                    </option>
                  ))}
                </select>
                <select
                  className="rounded-md border border-[#cfd8d1] px-3 py-2 text-sm outline-none transition focus:border-[#2f6f5f] focus:ring-2 focus:ring-[#a7e3cc]"
                  name="deviceId"
                  required
                >
                  {data.devices.map((device) => (
                    <option key={device.id} value={device.id}>
                      {device.name} | {device.project_name}
                    </option>
                  ))}
                </select>
                <select
                  className="rounded-md border border-[#cfd8d1] px-3 py-2 text-sm outline-none transition focus:border-[#2f6f5f] focus:ring-2 focus:ring-[#a7e3cc]"
                  name="scenario"
                  required
                >
                  {attackScenarios.map((scenario) => (
                    <option key={scenario.id} value={scenario.id}>
                      {scenario.label}
                    </option>
                  ))}
                </select>
                <button
                  className="inline-flex w-fit items-center gap-2 rounded-md bg-[#a33d3d] px-4 py-2 text-sm font-semibold text-white transition hover:bg-[#862f2f]"
                  disabled={data.projects.length === 0 || data.devices.length === 0}
                  type="submit"
                >
                  <Siren className="h-4 w-4" aria-hidden="true" />
                  Run simulation
                </button>
              </form>
            </section>
          </div>

          <div className="space-y-6">
            <section id="alerts" className="rounded-md border border-[#d8ded5] bg-white p-5 shadow-sm">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <h2 className="text-lg font-semibold">Open Alerts</h2>
                  <p className="mt-1 text-sm text-[#65736d]">High-confidence detections that need review.</p>
                </div>
                <ShieldAlert className="h-5 w-5 text-[#a33d3d]" aria-hidden="true" />
              </div>
              <div className="mt-4">
                <AlertList alerts={data.alerts} />
              </div>
            </section>

            <section className="overflow-hidden rounded-md border border-[#d8ded5] bg-white shadow-sm">
              <div className="flex items-center justify-between gap-3 p-5">
                <div>
                  <h2 className="text-lg font-semibold">Devices</h2>
                  <p className="mt-1 text-sm text-[#65736d]">Status, project, and last seen time.</p>
                </div>
                <Cpu className="h-5 w-5 text-[#2f6f5f]" aria-hidden="true" />
              </div>
              <div className="overflow-x-auto">
                <table className="w-full min-w-[760px] text-left">
                  <thead className="bg-[#f6f7f2] text-xs uppercase tracking-normal text-[#65736d]">
                    <tr>
                      <th className="px-4 py-3">Device</th>
                      <th className="px-4 py-3">Project</th>
                      <th className="px-4 py-3">Kind</th>
                      <th className="px-4 py-3">Status</th>
                      <th className="px-4 py-3">Last seen</th>
                    </tr>
                  </thead>
                  <tbody>
                    <DeviceRows devices={data.devices} />
                  </tbody>
                </table>
              </div>
            </section>

            <section className="overflow-hidden rounded-md border border-[#d8ded5] bg-white shadow-sm">
              <div className="flex items-center justify-between gap-3 p-5">
                <div>
                  <h2 className="text-lg font-semibold">Security Events</h2>
                  <p className="mt-1 text-sm text-[#65736d]">Threat score, verdict, and explanation.</p>
                </div>
                <ShieldAlert className="h-5 w-5 text-[#b7791f]" aria-hidden="true" />
              </div>
              <div className="overflow-x-auto">
                <table className="w-full min-w-[1220px] text-left">
                  <thead className="bg-[#f6f7f2] text-xs uppercase tracking-normal text-[#65736d]">
                    <tr>
                      <th className="px-4 py-3">Verdict</th>
                      <th className="px-4 py-3">Score</th>
                      <th className="px-4 py-3">Source IP</th>
                      <th className="px-4 py-3">Device</th>
                      <th className="px-4 py-3">Detection</th>
                      <th className="px-4 py-3">Reason</th>
                      <th className="px-4 py-3">Action</th>
                      <th className="px-4 py-3">Time</th>
                    </tr>
                  </thead>
                  <tbody>
                    <EventRows events={data.events} />
                  </tbody>
                </table>
              </div>
            </section>

            <section id="blocklist" className="rounded-md border border-[#d8ded5] bg-white p-5 shadow-sm">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <h2 className="text-lg font-semibold">IP Blocklist</h2>
                  <p className="mt-1 text-sm text-[#65736d]">The ingest API rejects active blocked sources.</p>
                </div>
                <Ban className="h-5 w-5 text-[#a33d3d]" aria-hidden="true" />
              </div>

              <form action="/api/blocklist" className="mt-4 grid gap-3 lg:grid-cols-[1fr_1fr_1fr_auto]" method="post">
                <select className="rounded-md border border-[#cfd8d1] px-3 py-2 text-sm outline-none transition focus:border-[#2f6f5f] focus:ring-2 focus:ring-[#a7e3cc]" name="projectId" required>
                  {data.projects.map((project) => (
                    <option key={project.id} value={project.id}>
                      {project.name}
                    </option>
                  ))}
                </select>
                <input className="rounded-md border border-[#cfd8d1] px-3 py-2 text-sm outline-none transition focus:border-[#2f6f5f] focus:ring-2 focus:ring-[#a7e3cc]" name="ip" placeholder="203.0.113.10" required />
                <input className="rounded-md border border-[#cfd8d1] px-3 py-2 text-sm outline-none transition focus:border-[#2f6f5f] focus:ring-2 focus:ring-[#a7e3cc]" name="reason" placeholder="Reason" />
                <button className="inline-flex items-center justify-center gap-2 rounded-md bg-[#a33d3d] px-4 py-2 text-sm font-semibold text-white transition hover:bg-[#862f2f]" disabled={data.projects.length === 0} type="submit">
                  <Ban className="h-4 w-4" aria-hidden="true" />
                  Block
                </button>
              </form>

              <div className="mt-4 grid gap-2">
                {data.blockedIps.length === 0 ? (
                  <p className="text-sm text-[#65736d]">No active IP blocks.</p>
                ) : (
                  data.blockedIps.map((block) => (
                    <div key={block.id} className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-[#efd1ce] bg-[#fff7f6] p-3">
                      <div>
                        <p className="font-mono text-sm font-semibold text-[#9f2d24]">{block.ip}</p>
                        <p className="mt-1 text-sm text-[#65736d]">{block.reason}</p>
                      </div>
                      <form action="/api/blocklist/disable" method="post">
                        <input name="blockId" type="hidden" value={block.id} />
                        <button className="rounded-md border border-[#d4b4af] bg-white px-3 py-2 text-sm font-semibold text-[#7a2d27] transition hover:border-[#9f2d24]" type="submit">
                          Unblock
                        </button>
                      </form>
                    </div>
                  ))
                )}
              </div>
            </section>
          </div>
        </section>
      </div>
    </main>
  );
}
