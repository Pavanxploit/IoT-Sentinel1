import { NextResponse } from "next/server";
import { getCurrentUser } from "@/lib/auth";
import { createDeviceForProject } from "@/lib/repository";

export const runtime = "nodejs";

export async function POST(request: Request) {
  const user = await getCurrentUser();

  if (!user) {
    return NextResponse.redirect(new URL("/login", request.url));
  }

  const form = await request.formData();
  const result = await createDeviceForProject(user.id, {
    projectId: String(form.get("projectId") ?? ""),
    name: String(form.get("name") ?? "").trim(),
    kind: String(form.get("kind") ?? "").trim(),
    location: String(form.get("location") ?? "").trim(),
    firmware: String(form.get("firmware") ?? "").trim(),
  });

  if (!result) {
    return NextResponse.redirect(new URL("/", request.url));
  }

  const url = new URL("/device-token", request.url);
  url.searchParams.set("projectId", result.device.project_id);
  url.searchParams.set("deviceId", result.device.id);
  url.searchParams.set("token", result.token);

  return NextResponse.redirect(url);
}
