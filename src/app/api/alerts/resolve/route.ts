import { NextResponse } from "next/server";
import { getCurrentUser } from "@/lib/auth";
import { resolveAlert } from "@/lib/repository";

export const runtime = "nodejs";

export async function POST(request: Request) {
  const user = await getCurrentUser();

  if (!user) {
    return NextResponse.redirect(new URL("/login", request.url));
  }

  const form = await request.formData();
  const alertId = String(form.get("alertId") ?? "");

  if (alertId) {
    await resolveAlert(user.id, alertId);
  }

  return NextResponse.redirect(new URL("/#alerts", request.url));
}
