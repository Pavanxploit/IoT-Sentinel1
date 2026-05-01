import Link from "next/link";
import { Database, KeyRound, Rocket } from "lucide-react";

export function SetupRequired() {
  return (
    <main className="min-h-screen bg-[#f6f7f2] px-5 py-8 text-[#17201c]">
      <div className="mx-auto flex min-h-[calc(100vh-4rem)] w-full max-w-6xl flex-col justify-center gap-8">
        <div className="grid gap-8 lg:grid-cols-[1fr_0.85fr] lg:items-center">
          <section className="space-y-6">
            <div className="inline-flex items-center gap-2 rounded-md border border-[#c9d8d0] bg-white px-3 py-2 text-sm font-medium text-[#2f6f5f]">
              <Database className="h-4 w-4" aria-hidden="true" />
              Database setup required
            </div>
            <div className="space-y-4">
              <h1 className="max-w-3xl text-4xl font-semibold leading-tight text-[#101816] sm:text-5xl">
                IoT Sentinel is ready for a database connection.
              </h1>
              <p className="max-w-2xl text-base leading-7 text-[#52625b]">
                Add a Neon or Postgres connection string before creating users, projects, devices,
                events, and IP blocks. The app creates its tables automatically on first request.
              </p>
            </div>
            <div className="grid gap-3 sm:grid-cols-3">
              <div className="rounded-md border border-[#d8ded5] bg-white p-4">
                <Database className="mb-4 h-5 w-5 text-[#2f6f5f]" aria-hidden="true" />
                <p className="text-sm font-semibold">DATABASE_URL</p>
                <p className="mt-2 text-sm leading-6 text-[#65736d]">Neon Postgres connection</p>
              </div>
              <div className="rounded-md border border-[#d8ded5] bg-white p-4">
                <KeyRound className="mb-4 h-5 w-5 text-[#b7791f]" aria-hidden="true" />
                <p className="text-sm font-semibold">AUTH_SECRET</p>
                <p className="mt-2 text-sm leading-6 text-[#65736d]">JWT cookie signing key</p>
              </div>
              <div className="rounded-md border border-[#d8ded5] bg-white p-4">
                <Rocket className="mb-4 h-5 w-5 text-[#a33d3d]" aria-hidden="true" />
                <p className="text-sm font-semibold">Vercel env vars</p>
                <p className="mt-2 text-sm leading-6 text-[#65736d]">Set them before deploy</p>
              </div>
            </div>
          </section>

          <section className="rounded-md border border-[#d8ded5] bg-[#101816] p-5 text-[#f7faf5] shadow-sm">
            <p className="text-sm font-semibold text-[#a7e3cc]">.env.local</p>
            <pre className="mt-4 overflow-x-auto rounded-md bg-black/30 p-4 text-sm leading-7 text-[#dce8e1]">
              <code>{`DATABASE_URL="postgresql://..."
AUTH_SECRET="generate-a-long-random-secret"`}</code>
            </pre>
            <p className="mt-5 text-sm leading-6 text-[#b8c9c0]">
              Generate a secret with{" "}
              <code className="rounded bg-white/10 px-1 py-0.5">
                node -e &quot;console.log(require(&apos;crypto&apos;).randomBytes(32).toString(&apos;hex&apos;))&quot;
              </code>
            </p>
            <Link
              className="mt-6 inline-flex items-center gap-2 rounded-md bg-[#a7e3cc] px-4 py-2 text-sm font-semibold text-[#0f1815] transition hover:bg-[#c6f4df]"
              href="/docs"
            >
              <Rocket className="h-4 w-4" aria-hidden="true" />
              Open setup guide
            </Link>
          </section>
        </div>
      </div>
    </main>
  );
}
