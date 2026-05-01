export function getRequestIp(request: Request, claimedIp?: string | null) {
  const forwarded = request.headers.get("x-forwarded-for");
  const realIp = request.headers.get("x-real-ip");
  const candidate =
    forwarded?.split(",")[0]?.trim() ||
    realIp?.trim() ||
    claimedIp?.trim() ||
    "unknown";

  return candidate.slice(0, 80);
}
