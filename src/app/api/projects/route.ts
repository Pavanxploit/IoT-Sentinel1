import { NextResponse } from "next/server";
import { getCurrentUser } from "@/lib/auth";
import { createProjectForUser } from "@/lib/repository";

export const runtime = "nodejs";

export async function POST(request: Request) {
  const user = await getCurrentUser();

  if (!user) {
    return NextResponse.redirect(new URL("/login", request.url));
  }

  const form = await request.formData();
  const name = String(form.get("name") ?? "").trim();
  const description = String(form.get("description") ?? "").trim();

  if (name) {
    await createProjectForUser(user.id, { name, description });
  }

  return NextResponse.redirect(new URL("/", request.url));
}
