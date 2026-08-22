import { proxyWithBody } from "@/lib/proxy";

export async function POST() {
  return proxyWithBody("/api/config/reset", "POST", {});
}
