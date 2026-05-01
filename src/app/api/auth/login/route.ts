import { NextResponse } from "next/server";
import { attachSessionCookie, createSessionToken } from "@/lib/auth";
import { findUserByEmail } from "@/lib/repository";
import { verifyPassword } from "@/lib/security";

export const runtime = "nodejs";

function redirectWithError(request: Request, error: string) {
  const url = new URL("/login", request.url);
  url.searchParams.set("error", error);
  return NextResponse.redirect(url);
}

export async function POST(request: Request) {
  try {
    const form = await request.formData();
    const email = String(form.get("email") ?? "");
    const password = String(form.get("password") ?? "");

    const user = await findUserByEmail(email);

    if (!user || !(await verifyPassword(password, user.password_hash))) {
      return redirectWithError(request, "invalid");
    }

    const response = NextResponse.redirect(new URL("/", request.url));
    attachSessionCookie(response, await createSessionToken(user));
    return response;
  } catch {
    return redirectWithError(request, "config");
  }
}
