import { NextResponse } from "next/server";
import { getCurrentUser } from "@/lib/auth";
import { runAttackSimulation } from "@/lib/repository";

export const runtime = "nodejs";

export async function POST(request: Request) {
  const user = await getCurrentUser();

  if (!user) {
    return NextResponse.redirect(new URL("/login", request.url));
  }

  const form = await request.formData();
  const result = await runAttackSimulation(user.id, {
    projectId: String(form.get("projectId") ?? ""),
    deviceId: String(form.get("deviceId") ?? ""),
    scenario: String(form.get("scenario") ?? ""),
  });

  const url = new URL("/#attack-lab", request.url);
  url.searchParams.set("simulation", result ? "created" : "failed");
  return NextResponse.redirect(url);
}
