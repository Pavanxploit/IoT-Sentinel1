import { NextResponse } from "next/server";
import { getCurrentUser } from "@/lib/auth";
import { createManualBlock } from "@/lib/repository";

export const runtime = "nodejs";

export async function POST(request: Request) {
  const user = await getCurrentUser();

  if (!user) {
    return NextResponse.redirect(new URL("/login", request.url));
  }

  const form = await request.formData();
  await createManualBlock(user.id, {
    projectId: String(form.get("projectId") ?? ""),
    ip: String(form.get("ip") ?? "").trim(),
    reason: String(form.get("reason") ?? "").trim(),
  });

  return NextResponse.redirect(new URL("/#blocklist", request.url));
}
