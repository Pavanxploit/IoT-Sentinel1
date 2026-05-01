import { NextResponse } from "next/server";
import { z } from "zod";
import { analyzePayload } from "@/lib/risk";
import { getRequestIp } from "@/lib/request";
import {
  findActiveBlock,
  getRecentIpEventCount,
  recordSecurityEvent,
  updateDeviceSeen,
  upsertBlockedIp,
  verifyDeviceToken,
} from "@/lib/repository";

export const runtime = "nodejs";

const packetSchema = z
  .object({
    protocol: z.string().max(32).optional(),
    srcPort: z.coerce.number().int().min(0).max(65535).optional(),
    destPort: z.coerce.number().int().min(0).max(65535).optional(),
    bytes: z.coerce.number().int().min(0).max(10_000_000).optional(),
    flags: z.union([z.array(z.string().max(24)), z.string().max(160)]).optional(),
    payload: z.string().max(4000).optional(),
    path: z.string().max(512).optional(),
  })
  .passthrough();

const ingestSchema = z
  .object({
    projectId: z.string().optional(),
    deviceId: z.string().optional(),
    deviceToken: z.string().optional(),
    eventType: z.string().max(80).default("telemetry"),
    severity: z.enum(["info", "low", "medium", "high", "critical"]).default("info"),
    message: z.string().max(4000).optional(),
    logs: z.array(z.string().max(1000)).max(50).optional(),
    packet: packetSchema.optional(),
    telemetry: z.record(z.string(), z.unknown()).optional(),
    sourceIp: z.string().max(80).optional(),
  })
  .passthrough();

function bearerToken(request: Request) {
  const authorization = request.headers.get("authorization");
  const match = authorization?.match(/^Bearer\s+(.+)$/i);
  return match?.[1] ?? request.headers.get("x-device-token");
}

export async function POST(request: Request) {
  let rawBody: unknown;

  try {
    rawBody = await request.json();
  } catch {
    return NextResponse.json({ accepted: false, error: "invalid_json" }, { status: 400 });
  }

  const parsed = ingestSchema.safeParse(rawBody);

  if (!parsed.success) {
    return NextResponse.json(
      {
        accepted: false,
        error: "invalid_payload",
        details: parsed.error.flatten().fieldErrors,
      },
      { status: 400 },
    );
  }

  const body = parsed.data;
  const projectId = request.headers.get("x-project-id") ?? body.projectId;
  const deviceId = request.headers.get("x-device-id") ?? body.deviceId;
  const token = bearerToken(request) ?? body.deviceToken;

  if (!projectId || !deviceId || !token) {
    return NextResponse.json(
      {
        accepted: false,
        error: "missing_credentials",
        required: ["x-project-id", "x-device-id", "authorization: Bearer <device-token>"],
      },
      { status: 401 },
    );
  }

  const credentials = await verifyDeviceToken(projectId, deviceId, token);

  if (!credentials) {
    return NextResponse.json({ accepted: false, error: "unauthorized_device" }, { status: 401 });
  }

  const sourceIp = getRequestIp(request, body.sourceIp);
  const activeBlock = await findActiveBlock(projectId, sourceIp);
  const recentIpEvents = await getRecentIpEventCount(projectId, sourceIp);
  const firmware =
    typeof body.telemetry?.firmware === "string" ? String(body.telemetry.firmware) : undefined;

  const analysis = analyzePayload({
    ...body,
    sourceIp,
    recentIpEvents,
    alreadyBlocked: Boolean(activeBlock),
  });

  const event = await recordSecurityEvent({
    projectId,
    deviceId,
    sourceIp,
    eventType: body.eventType,
    severity: body.severity,
    analysis,
    packet: body.packet ?? {},
    raw: rawBody && typeof rawBody === "object" ? (rawBody as Record<string, unknown>) : {},
  });

  if (activeBlock) {
    return NextResponse.json(
      {
        accepted: false,
        eventId: event.id,
        verdict: "blocked",
        score: analysis.score,
        signals: analysis.signals,
      },
      { status: 403 },
    );
  }

  await updateDeviceSeen(deviceId, sourceIp, firmware);

  let blocked = false;
  if (credentials.project.autoBlock && analysis.score >= credentials.project.riskThreshold) {
    await upsertBlockedIp({
      projectId,
      ip: sourceIp,
      reason: analysis.summary,
      score: analysis.score,
    });
    blocked = true;
  }

  return NextResponse.json(
    {
      accepted: true,
      eventId: event.id,
      verdict: analysis.verdict,
      score: analysis.score,
      blocked,
      signals: analysis.signals,
    },
    { status: 202 },
  );
}
