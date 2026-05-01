import { NextResponse } from "next/server";
import { getCurrentUser } from "@/lib/auth";
import { disableBlock } from "@/lib/repository";

export const runtime = "nodejs";

export async function POST(request: Request) {
  const user = await getCurrentUser();

  if (!user) {
    return NextResponse.redirect(new URL("/login", request.url));
  }

  const form = await request.formData();
  const blockId = String(form.get("blockId") ?? "");

  if (blockId) {
    await disableBlock(user.id, blockId);
  }

  return NextResponse.redirect(new URL("/#blocklist", request.url));
}
