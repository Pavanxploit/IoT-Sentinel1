import Link from "next/link";
import { redirect } from "next/navigation";
import { Copy, ShieldCheck } from "lucide-react";
import { getCurrentUser } from "@/lib/auth";
import { getProjectForUser } from "@/lib/repository";

export const dynamic = "force-dynamic";

type SearchParams = Promise<Record<string, string | string[] | undefined>>;

function asString(value: string | string[] | undefined) {
  return Array.isArray(value) ? value[0] : value;
}

export default async function DeviceTokenPage({ searchParams }: { searchParams?: SearchParams }) {
  const user = await getCurrentUser();

  if (!user) {
    redirect("/login");
  }

  const params = searchParams ? await searchParams : {};
  const projectId = asString(params.projectId);
  const deviceId = asString(params.deviceId);
  const token = asString(params.token);

  if (!projectId || !deviceId || !token) {
    redirect("/");
  }

  const project = await getProjectForUser(user.id, projectId);

  if (!project) {
    redirect("/");
  }

  return (
    <main className="min-h-screen bg-[#f6f7f2] px-5 py-8 text-[#17201c]">
      <div className="mx-auto w-full max-w-4xl">
        <Link className="mb-8 inline-flex items-center gap-3" href="/">
          <span className="flex h-10 w-10 items-center justify-center rounded-md bg-[#17201c] text-[#a7e3cc]">
            <ShieldCheck className="h-5 w-5" aria-hidden="true" />
          </span>
          <span className="font-semibold">Back to dashboard</span>
        </Link>

        <section className="rounded-md border border-[#d8ded5] bg-white p-6 shadow-sm">
          <h1 className="text-3xl font-semibold">Device token created</h1>
          <p className="mt-2 text-sm leading-6 text-[#65736d]">
            This secret is shown once. Store it in your device firmware config or a secure build
            secret. Rotate the device if this URL is shared.
          </p>

          <div className="mt-6 grid gap-4">
            <div>
              <p className="text-sm font-semibold text-[#65736d]">Project</p>
              <p className="mt-1 font-mono text-sm">{project.name} ({projectId})</p>
            </div>
            <div>
              <p className="text-sm font-semibold text-[#65736d]">Device ID</p>
              <p className="mt-1 break-all font-mono text-sm">{deviceId}</p>
            </div>
            <div>
              <p className="text-sm font-semibold text-[#65736d]">Device token</p>
              <p className="mt-1 break-all rounded-md border border-[#cfd8d1] bg-[#f6f7f2] p-3 font-mono text-sm">
                {token}
              </p>
            </div>
          </div>

          <div className="mt-6 rounded-md border border-[#d8ded5] bg-[#101816] p-4 text-[#f7faf5]">
            <p className="mb-3 flex items-center gap-2 text-sm font-semibold text-[#a7e3cc]">
              <Copy className="h-4 w-4" aria-hidden="true" />
              Test ingest request
            </p>
            <pre className="overflow-x-auto text-sm leading-7">
              <code>{`curl -X POST https://your-domain.vercel.app/api/ingest \\
  -H "content-type: application/json" \\
  -H "x-project-id: ${projectId}" \\
  -H "x-device-id: ${deviceId}" \\
  -H "authorization: Bearer ${token}" \\
  -d '{"eventType":"network","severity":"high","message":"telnet brute force","packet":{"protocol":"tcp","destPort":23,"bytes":2048}}'`}</code>
            </pre>
          </div>
        </section>
      </div>
    </main>
  );
}
