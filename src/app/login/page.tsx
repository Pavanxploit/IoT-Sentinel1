import Link from "next/link";
import Image from "next/image";
import { redirect } from "next/navigation";
import { LogIn, ShieldCheck } from "lucide-react";
import { getCurrentUser } from "@/lib/auth";
import { isDatabaseConfigured } from "@/lib/db";
import { SetupRequired } from "@/components/setup-required";

export const dynamic = "force-dynamic";

type SearchParams = Promise<Record<string, string | string[] | undefined>>;

const errorMessages: Record<string, string> = {
  invalid: "Email or password was not correct.",
  config: "The app needs a working DATABASE_URL and AUTH_SECRET.",
};

export default async function LoginPage({ searchParams }: { searchParams?: SearchParams }) {
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
      <div className="mx-auto grid min-h-[calc(100vh-4rem)] w-full max-w-6xl gap-8 lg:grid-cols-[1fr_0.8fr] lg:items-center">
        <section className="space-y-6">
          <Link className="inline-flex items-center gap-3" href="/">
            <span className="flex h-11 w-11 items-center justify-center rounded-md bg-[#17201c] text-[#a7e3cc]">
              <ShieldCheck className="h-5 w-5" aria-hidden="true" />
            </span>
            <span>
              <span className="block text-lg font-semibold">IoT Sentinel</span>
              <span className="block text-xs text-[#65736d]">Secure ingest for small IoT fleets</span>
            </span>
          </Link>
          <div className="max-w-2xl space-y-4">
            <h1 className="text-4xl font-semibold leading-tight sm:text-5xl">
              Analyze IoT logs, score threats, and isolate bad IPs.
            </h1>
            <p className="text-base leading-7 text-[#52625b]">
              Each project has its own members, devices, ingest tokens, event history, risk
              verdicts, and blocklist. ESP32 devices can post compact JSON over HTTPS.
            </p>
          </div>
          <Image
            alt="IoT device telemetry and security flow"
            className="w-full max-w-xl rounded-md border border-[#d8ded5] bg-white shadow-sm"
            height={620}
            src="/iot-sentinel-board.svg"
            width={1120}
          />
        </section>

        <section className="rounded-md border border-[#d8ded5] bg-white p-6 shadow-sm">
          <h2 className="text-2xl font-semibold">Sign in</h2>
          <p className="mt-2 text-sm leading-6 text-[#65736d]">
            Use the account you created for your IoT project workspace.
          </p>

          {error ? (
            <p className="mt-4 rounded-md border border-[#f3b9b1] bg-[#fde2df] px-3 py-2 text-sm text-[#9f2d24]">
              {error}
            </p>
          ) : null}

          <form action="/api/auth/login" className="mt-5 grid gap-4" method="post">
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
                autoComplete="current-password"
                className="rounded-md border border-[#cfd8d1] px-3 py-2 outline-none transition focus:border-[#2f6f5f] focus:ring-2 focus:ring-[#a7e3cc]"
                name="password"
                required
                type="password"
              />
            </label>
            <button className="inline-flex items-center justify-center gap-2 rounded-md bg-[#17201c] px-4 py-2 font-semibold text-white transition hover:bg-[#2d3a34]" type="submit">
              <LogIn className="h-4 w-4" aria-hidden="true" />
              Sign in
            </button>
          </form>

          <p className="mt-5 text-sm text-[#65736d]">
            New workspace?{" "}
            <Link className="font-semibold text-[#2f6f5f] hover:text-[#235a4d]" href="/register">
              Create an account
            </Link>
          </p>
        </section>
      </div>
    </main>
  );
}
