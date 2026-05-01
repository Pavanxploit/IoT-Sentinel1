import { NextResponse } from "next/server";
import { ensureSchema, isDatabaseConfigured } from "@/lib/db";

export const runtime = "nodejs";

export async function GET() {
  if (!isDatabaseConfigured()) {
    return NextResponse.json(
      {
        ok: false,
        status: "missing_database_url",
      },
      { status: 503 },
    );
  }

  try {
    await ensureSchema();
    return NextResponse.json({
      ok: true,
      status: "ready",
    });
  } catch (error) {
    return NextResponse.json(
      {
        ok: false,
        status: "database_error",
        message: error instanceof Error ? error.message : "Unknown error",
      },
      { status: 500 },
    );
  }
}
