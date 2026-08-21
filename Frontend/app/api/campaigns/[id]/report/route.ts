import { NextRequest } from "next/server";
import { proxyText } from "@/lib/proxy";

export async function GET(_req: NextRequest, context: { params: Promise<{ id: string }> }) {
  const { id } = await context.params;
  return proxyText(`/api/campaigns/${encodeURIComponent(id)}/report`, `campaign-${id}.md`);
}
