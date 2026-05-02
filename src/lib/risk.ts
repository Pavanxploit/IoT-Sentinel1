export type PacketSummary = {
  protocol?: string;
  srcPort?: number;
  destPort?: number;
  bytes?: number;
  flags?: string[] | string;
  payload?: string;
  path?: string;
};

export type IngestPayload = {
  eventType?: string;
  severity?: string;
  message?: string;
  logs?: string[];
  packet?: PacketSummary;
  telemetry?: Record<string, unknown>;
};

export type RiskInput = IngestPayload & {
  sourceIp: string;
  recentIpEvents: number;
  alreadyBlocked: boolean;
};

export type RiskVerdict = "clean" | "suspicious" | "malicious";
export type DetectionCategory =
  | "baseline"
  | "credential_attack"
  | "malware_delivery"
  | "reconnaissance"
  | "iot_protocol_abuse"
  | "command_injection"
  | "data_exfiltration"
  | "blocked_source"
  | "traffic_anomaly";

export type RiskResult = {
  score: number;
  verdict: RiskVerdict;
  category: DetectionCategory;
  confidence: number;
  summary: string;
  signals: string[];
  recommendedAction: string;
};

const riskyPorts = new Set([21, 22, 23, 25, 53, 80, 139, 445, 2323, 3389, 5900, 8080, 8443]);
const malwareTerms = [
  "mirai",
  "gafgyt",
  "bashlite",
  "botnet",
  "cnc",
  "c2",
  "wget ",
  "curl ",
  "/bin/sh",
  "busybox",
  "telnetd",
  "nc ",
  "netcat",
  "chmod +x",
  "base64 -d",
  "miner",
  "cryptominer",
];

const authAbuseTerms = [
  "failed password",
  "invalid user",
  "default password",
  "admin:admin",
  "root:root",
  "bruteforce",
  "brute force",
];

const injectionTerms = ["../", "%2e%2e", "union select", "<script", " or 1=1", ";cat ", ";wget", "|sh"];

function compactText(input: RiskInput) {
  return [
    input.eventType,
    input.severity,
    input.message,
    input.packet?.protocol,
    input.packet?.payload,
    input.packet?.path,
    ...(input.logs ?? []),
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
}

function add(score: number, points: number) {
  return Math.min(100, score + points);
}

function telemetryNumber(input: RiskInput, key: string) {
  const value = input.telemetry?.[key];
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

function recommendedAction(category: DetectionCategory, verdict: RiskVerdict) {
  if (category === "blocked_source") {
    return "Keep source IP blocked, review repeated attempts, and consider upstream firewall enforcement.";
  }

  if (category === "credential_attack") {
    return "Rotate weak credentials, disable default passwords, and rate-limit authentication paths.";
  }

  if (category === "malware_delivery" || category === "command_injection") {
    return "Quarantine the device, capture firmware state, and rotate device tokens before reconnecting.";
  }

  if (category === "reconnaissance") {
    return "Review exposed services and restrict management ports to trusted networks.";
  }

  if (category === "iot_protocol_abuse") {
    return "Inspect MQTT/CoAP topics, validate broker ACLs, and block replay sources.";
  }

  if (category === "data_exfiltration") {
    return "Inspect payload destination, compare against expected device behavior, and pause outbound traffic.";
  }

  if (verdict === "malicious") {
    return "Block source IP, investigate the device, and open an incident ticket.";
  }

  if (verdict === "suspicious") {
    return "Monitor closely and compare with recent device baseline.";
  }

  return "No action required beyond normal monitoring.";
}

export function analyzePayload(input: RiskInput): RiskResult {
  let score = 0;
  const signals: string[] = [];
  const categories = new Set<DetectionCategory>();
  const text = compactText(input);
  const packet = input.packet ?? {};
  const severity = input.severity?.toLowerCase();
  const authFailures = telemetryNumber(input, "authFailures");
  const connectionAttempts = telemetryNumber(input, "connectionAttempts");
  const uniquePorts = telemetryNumber(input, "uniquePorts");
  const outboundBytes = telemetryNumber(input, "outboundBytes");

  if (input.alreadyBlocked) {
    score = add(score, 100);
    categories.add("blocked_source");
    signals.push("Source IP is already in the active blocklist");
  }

  if (severity === "critical") {
    score = add(score, 35);
    signals.push("Device reported critical severity");
  } else if (severity === "high") {
    score = add(score, 24);
    signals.push("Device reported high severity");
  } else if (severity === "medium") {
    score = add(score, 12);
    signals.push("Device reported medium severity");
  }

  if (packet.destPort && riskyPorts.has(packet.destPort)) {
    score = add(score, packet.destPort === 23 || packet.destPort === 2323 ? 24 : 14);
    categories.add(packet.destPort === 23 || packet.destPort === 2323 ? "credential_attack" : "reconnaissance");
    signals.push(`Traffic touched sensitive port ${packet.destPort}`);
  }

  if (packet.bytes && packet.bytes > 150_000) {
    score = add(score, 12);
    categories.add("data_exfiltration");
    signals.push("Packet summary shows unusually large transfer");
  }

  if (outboundBytes > 500_000) {
    score = add(score, 22);
    categories.add("data_exfiltration");
    signals.push("Telemetry shows unusual outbound transfer volume");
  }

  if (input.recentIpEvents > 500) {
    score = add(score, 34);
    categories.add("traffic_anomaly");
    signals.push("Very high event rate from the same source IP");
  } else if (input.recentIpEvents > 100) {
    score = add(score, 20);
    categories.add("traffic_anomaly");
    signals.push("High event rate from the same source IP");
  } else if (input.recentIpEvents > 30) {
    score = add(score, 10);
    categories.add("traffic_anomaly");
    signals.push("Elevated event rate from the same source IP");
  }

  if (connectionAttempts > 120 || uniquePorts > 15) {
    score = add(score, 26);
    categories.add("reconnaissance");
    signals.push("Telemetry indicates scanning behavior across services");
  }

  if (authFailures > 20) {
    score = add(score, authFailures > 100 ? 32 : 22);
    categories.add("credential_attack");
    signals.push("Telemetry reports repeated authentication failures");
  }

  for (const term of malwareTerms) {
    if (text.includes(term)) {
      score = add(score, 26);
      categories.add("malware_delivery");
      signals.push(`Malware indicator matched: ${term.trim()}`);
      break;
    }
  }

  for (const term of authAbuseTerms) {
    if (text.includes(term)) {
      score = add(score, 18);
      categories.add("credential_attack");
      signals.push(`Authentication abuse indicator matched: ${term}`);
      break;
    }
  }

  for (const term of injectionTerms) {
    if (text.includes(term)) {
      score = add(score, 20);
      categories.add("command_injection");
      signals.push(`Injection indicator matched: ${term}`);
      break;
    }
  }

  if (text.includes("port scan") || text.includes("syn scan") || text.includes("nmap")) {
    score = add(score, 24);
    categories.add("reconnaissance");
    signals.push("Scan behavior was reported");
  }

  if (text.includes("mqtt flood") || text.includes("replay attack")) {
    score = add(score, 30);
    categories.add("iot_protocol_abuse");
    signals.push("IoT protocol abuse was reported");
  }

  const verdict: RiskResult["verdict"] =
    score >= 75 ? "malicious" : score >= 45 ? "suspicious" : "clean";
  const category = categories.values().next().value ?? "baseline";
  const confidence = Math.min(99, Math.max(35, score + signals.length * 5));

  const summary =
    signals.length > 0
      ? signals.slice(0, 2).join("; ")
      : "No high-confidence malicious indicators were found";

  return {
    score,
    verdict,
    category,
    confidence,
    summary,
    signals,
    recommendedAction: recommendedAction(category, verdict),
  };
}
