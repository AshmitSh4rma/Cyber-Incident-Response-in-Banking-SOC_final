import { NextRequest } from "next/server";
import { proxyJson } from "@/lib/proxy";

export async function GET(_req: NextRequest, context: { params: Promise<{ id: string }> }) {
  const { id } = await context.params;
  return proxyJson(`/api/campaigns/${encodeURIComponent(id)}`);
}
