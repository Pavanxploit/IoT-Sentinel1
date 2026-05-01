import { neon } from "@neondatabase/serverless";

const databaseUrl = process.env.DATABASE_URL;

if (!databaseUrl) {
  console.error("DATABASE_URL is required.");
  process.exit(1);
}

const query = neon(databaseUrl);

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
    summary text NOT NULL,
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

console.log("Database schema is ready.");
