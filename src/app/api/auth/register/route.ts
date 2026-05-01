import { NextResponse } from "next/server";
import { attachSessionCookie, createSessionToken } from "@/lib/auth";
import { createUserWithWorkspace, findUserByEmail } from "@/lib/repository";
import { hashPassword } from "@/lib/security";

export const runtime = "nodejs";

function redirectWithError(request: Request, error: string) {
  const url = new URL("/register", request.url);
  url.searchParams.set("error", error);
  return NextResponse.redirect(url);
}

export async function POST(request: Request) {
  try {
    const form = await request.formData();
    const name = String(form.get("name") ?? "").trim();
    const email = String(form.get("email") ?? "").trim();
    const password = String(form.get("password") ?? "");

    if (!name || !email || password.length < 8) {
      return redirectWithError(request, "invalid");
    }

    if (await findUserByEmail(email)) {
      return redirectWithError(request, "exists");
    }

    const user = await createUserWithWorkspace({
      name,
      email,
      passwordHash: await hashPassword(password),
    });

    const response = NextResponse.redirect(new URL("/?welcome=1", request.url));
    attachSessionCookie(response, await createSessionToken(user));
    return response;
  } catch {
    return redirectWithError(request, "config");
  }
}
