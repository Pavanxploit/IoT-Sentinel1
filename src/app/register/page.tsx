import Link from "next/link";
import Image from "next/image";
import { redirect } from "next/navigation";
import { ShieldCheck, UserPlus } from "lucide-react";
import { getCurrentUser } from "@/lib/auth";
import { isDatabaseConfigured } from "@/lib/db";
import { SetupRequired } from "@/components/setup-required";

export const dynamic = "force-dynamic";

type SearchParams = Promise<Record<string, string | string[] | undefined>>;

const errorMessages: Record<string, string> = {
  invalid: "Use a name, valid email, and password with at least 8 characters.",
  exists: "An account already exists for that email.",
  config: "The app needs a working DATABASE_URL and AUTH_SECRET.",
};

export default async function RegisterPage({ searchParams }: { searchParams?: SearchParams }) {
  if (!isDatabaseConfigured()) {
    return <SetupRequired />;
  }

  const user = await getCurrentUser();

  if (user) {
    redirect("/");
  }

  const params = searchParams ? await searchParams : {};
  const error = typeof params.error === "string" ? errorMessages[params.error] : null;

  return (
    <main className="min-h-screen bg-[#f6f7f2] px-5 py-8 text-[#17201c]">
      <div className="mx-auto grid min-h-[calc(100vh-4rem)] w-full max-w-6xl gap-8 lg:grid-cols-[0.9fr_1fr] lg:items-center">
        <section className="rounded-md border border-[#d8ded5] bg-white p-6 shadow-sm">
          <Link className="mb-8 inline-flex items-center gap-3" href="/">
            <span className="flex h-11 w-11 items-center justify-center rounded-md bg-[#17201c] text-[#a7e3cc]">
              <ShieldCheck className="h-5 w-5" aria-hidden="true" />
            </span>
            <span>
              <span className="block text-lg font-semibold">IoT Sentinel</span>
              <span className="block text-xs text-[#65736d]">Create your control plane</span>
            </span>
          </Link>

          <h1 className="text-3xl font-semibold">Create workspace</h1>
          <p className="mt-2 text-sm leading-6 text-[#65736d]">
            Registration creates a private project and membership row for you.
          </p>

          {error ? (
            <p className="mt-4 rounded-md border border-[#f3b9b1] bg-[#fde2df] px-3 py-2 text-sm text-[#9f2d24]">
              {error}
            </p>
          ) : null}

          <form action="/api/auth/register" className="mt-5 grid gap-4" method="post">
            <label className="grid gap-2 text-sm font-medium">
              Name
              <input
                autoComplete="name"
                className="rounded-md border border-[#cfd8d1] px-3 py-2 outline-none transition focus:border-[#2f6f5f] focus:ring-2 focus:ring-[#a7e3cc]"
                name="name"
                required
              />
            </label>
            <label className="grid gap-2 text-sm font-medium">
              Email
              <input
                autoComplete="email"
                className="rounded-md border border-[#cfd8d1] px-3 py-2 outline-none transition focus:border-[#2f6f5f] focus:ring-2 focus:ring-[#a7e3cc]"
                name="email"
                required
                type="email"
              />
            </label>
            <label className="grid gap-2 text-sm font-medium">
              Password
              <input
                autoComplete="new-password"
                className="rounded-md border border-[#cfd8d1] px-3 py-2 outline-none transition focus:border-[#2f6f5f] focus:ring-2 focus:ring-[#a7e3cc]"
                minLength={8}
                name="password"
                required
                type="password"
              />
            </label>
            <button className="inline-flex items-center justify-center gap-2 rounded-md bg-[#2f6f5f] px-4 py-2 font-semibold text-white transition hover:bg-[#235a4d]" type="submit">
              <UserPlus className="h-4 w-4" aria-hidden="true" />
              Create account
            </button>
          </form>

          <p className="mt-5 text-sm text-[#65736d]">
            Already registered?{" "}
            <Link className="font-semibold text-[#2f6f5f] hover:text-[#235a4d]" href="/login">
              Sign in
            </Link>
          </p>
        </section>

        <section className="space-y-5">
          <Image
            alt="IoT security telemetry dashboard"
            className="w-full rounded-md border border-[#d8ded5] bg-white shadow-sm"
            height={620}
            src="/iot-sentinel-board.svg"
            width={1120}
          />
          <div className="grid gap-3 sm:grid-cols-3">
            <div className="rounded-md border border-[#d8ded5] bg-white p-4">
              <p className="font-semibold">Project isolation</p>
              <p className="mt-2 text-sm leading-6 text-[#65736d]">Users only see projects they belong to.</p>
            </div>
            <div className="rounded-md border border-[#d8ded5] bg-white p-4">
              <p className="font-semibold">Device tokens</p>
              <p className="mt-2 text-sm leading-6 text-[#65736d]">Each node has a separate ingest credential.</p>
            </div>
            <div className="rounded-md border border-[#d8ded5] bg-white p-4">
              <p className="font-semibold">Auto block</p>
              <p className="mt-2 text-sm leading-6 text-[#65736d]">Malicious sources are rejected by the API.</p>
            </div>
          </div>
        </section>
      </div>
    </main>
  );
}
