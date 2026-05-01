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

export type RiskResult = {
  score: number;
  verdict: RiskVerdict;
  summary: string;
  signals: string[];
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

export function analyzePayload(input: RiskInput): RiskResult {
  let score = 0;
  const signals: string[] = [];
  const text = compactText(input);
  const packet = input.packet ?? {};
  const severity = input.severity?.toLowerCase();

  if (input.alreadyBlocked) {
    score = add(score, 100);
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
    signals.push(`Traffic touched sensitive port ${packet.destPort}`);
  }

  if (packet.bytes && packet.bytes > 150_000) {
    score = add(score, 12);
    signals.push("Packet summary shows unusually large transfer");
  }

  if (input.recentIpEvents > 500) {
    score = add(score, 34);
    signals.push("Very high event rate from the same source IP");
  } else if (input.recentIpEvents > 100) {
    score = add(score, 20);
    signals.push("High event rate from the same source IP");
  } else if (input.recentIpEvents > 30) {
    score = add(score, 10);
    signals.push("Elevated event rate from the same source IP");
  }

  for (const term of malwareTerms) {
    if (text.includes(term)) {
      score = add(score, 26);
      signals.push(`Malware indicator matched: ${term.trim()}`);
      break;
    }
  }

  for (const term of authAbuseTerms) {
    if (text.includes(term)) {
      score = add(score, 18);
      signals.push(`Authentication abuse indicator matched: ${term}`);
      break;
    }
  }

  for (const term of injectionTerms) {
    if (text.includes(term)) {
      score = add(score, 20);
      signals.push(`Injection indicator matched: ${term}`);
      break;
    }
  }

  if (text.includes("port scan") || text.includes("syn scan") || text.includes("nmap")) {
    score = add(score, 24);
    signals.push("Scan behavior was reported");
  }

  if (text.includes("mqtt flood") || text.includes("replay attack")) {
    score = add(score, 30);
    signals.push("IoT protocol abuse was reported");
  }

  const verdict: RiskResult["verdict"] =
    score >= 75 ? "malicious" : score >= 45 ? "suspicious" : "clean";

  const summary =
    signals.length > 0
      ? signals.slice(0, 2).join("; ")
      : "No high-confidence malicious indicators were found";

  return {
    score,
    verdict,
    summary,
    signals,
  };
}
