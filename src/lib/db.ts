import { neon } from "@neondatabase/serverless";

type SqlClient = ReturnType<typeof neon>;

let client: SqlClient | null = null;
let schemaReady: Promise<void> | null = null;

export class DatabaseConfigError extends Error {
  constructor() {
    super("DATABASE_URL is not configured.");
    this.name = "DatabaseConfigError";
  }
}

export function isDatabaseConfigured() {
  return Boolean(process.env.DATABASE_URL);
}

export function getSql() {
  const databaseUrl = process.env.DATABASE_URL;

  if (!databaseUrl) {
    throw new DatabaseConfigError();
  }

  if (!client) {
    client = neon(databaseUrl);
  }

  return client;
}

export async function sql<T extends Record<string, unknown> = Record<string, unknown>>(
  strings: TemplateStringsArray,
  ...values: unknown[]
) {
  const rows = await getSql()(strings, ...values);
  return rows as T[];
}

export async function ensureSchema() {
  if (!schemaReady) {
    schemaReady = createSchema().catch((error) => {
      schemaReady = null;
      throw error;
    });
  }

  return schemaReady;
}

async function createSchema() {
  const query = getSql();

  await query`
    CREATE TABLE IF NOT EXISTS app_users (
      id text PRIMARY KEY,
      name text NOT NULL,
      email text UNIQUE NOT NULL,
      password_hash text NOT NULL,
      role text NOT NULL DEFAULT 'operator',
      created_at timestamptz NOT NULL DEFAULT now()
    )
  `;

  await query`
    CREATE TABLE IF NOT EXISTS projects (
      id text PRIMARY KEY,
      name text NOT NULL,
      slug text NOT NULL,
      description text NOT NULL DEFAULT '',
      owner_user_id text NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
      risk_threshold integer NOT NULL DEFAULT 75,
      auto_block boolean NOT NULL DEFAULT true,
      created_at timestamptz NOT NULL DEFAULT now()
    )
  `;

  await query`
    CREATE TABLE IF NOT EXISTS project_members (
      project_id text NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      user_id text NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
      role text NOT NULL DEFAULT 'viewer',
      created_at timestamptz NOT NULL DEFAULT now(),
      PRIMARY KEY (project_id, user_id)
    )
  `;

  await query`
    CREATE TABLE IF NOT EXISTS devices (
      id text PRIMARY KEY,
      project_id text NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      name text NOT NULL,
      kind text NOT NULL DEFAULT 'iot-node',
      location text NOT NULL DEFAULT '',
      firmware text NOT NULL DEFAULT '',
      device_key_hash text NOT NULL,
      status text NOT NULL DEFAULT 'provisioned',
      last_seen_at timestamptz,
      last_ip text,
      created_at timestamptz NOT NULL DEFAULT now()
    )
  `;

  await query`
    CREATE TABLE IF NOT EXISTS events (
      id text PRIMARY KEY,
      project_id text NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      device_id text REFERENCES devices(id) ON DELETE SET NULL,
      source_ip text NOT NULL,
      event_type text NOT NULL,
      severity text NOT NULL,
      score integer NOT NULL,
      verdict text NOT NULL,
      category text NOT NULL DEFAULT 'baseline',
      confidence integer NOT NULL DEFAULT 35,
      summary text NOT NULL,
      recommended_action text NOT NULL DEFAULT 'No action required beyond normal monitoring.',
      signals jsonb NOT NULL DEFAULT '[]'::jsonb,
      packet jsonb NOT NULL DEFAULT '{}'::jsonb,
      raw jsonb NOT NULL DEFAULT '{}'::jsonb,
      created_at timestamptz NOT NULL DEFAULT now()
    )
  `;

  await query`
    CREATE TABLE IF NOT EXISTS blocked_ips (
      id text PRIMARY KEY,
      project_id text NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      ip text NOT NULL,
      reason text NOT NULL,
      score integer NOT NULL DEFAULT 0,
      active boolean NOT NULL DEFAULT true,
      created_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (project_id, ip)
    )
  `;

  await query`
    CREATE TABLE IF NOT EXISTS alerts (
      id text PRIMARY KEY,
      project_id text NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      event_id text REFERENCES events(id) ON DELETE SET NULL,
      severity text NOT NULL,
      title text NOT NULL,
      description text NOT NULL,
      action text NOT NULL,
      resolved boolean NOT NULL DEFAULT false,
      created_at timestamptz NOT NULL DEFAULT now(),
      resolved_at timestamptz
    )
  `;

  await query`
    ALTER TABLE events
      ADD COLUMN IF NOT EXISTS category text NOT NULL DEFAULT 'baseline',
      ADD COLUMN IF NOT EXISTS confidence integer NOT NULL DEFAULT 35,
      ADD COLUMN IF NOT EXISTS recommended_action text NOT NULL DEFAULT 'No action required beyond normal monitoring.'
  `;

  await query`
    CREATE INDEX IF NOT EXISTS idx_events_project_created
      ON events (project_id, created_at DESC)
  `;

  await query`
    CREATE INDEX IF NOT EXISTS idx_events_project_ip_created
      ON events (project_id, source_ip, created_at DESC)
  `;

  await query`
    CREATE INDEX IF NOT EXISTS idx_devices_project_seen
      ON devices (project_id, last_seen_at DESC)
  `;

  await query`
    CREATE INDEX IF NOT EXISTS idx_blocked_ips_project_active
      ON blocked_ips (project_id, active)
  `;

  await query`
    CREATE INDEX IF NOT EXISTS idx_alerts_project_open
      ON alerts (project_id, resolved, created_at DESC)
  `;
}
