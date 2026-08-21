import { redirect } from "next/navigation";

// The console's real entry point is the incident dashboard. Landing on "/"
// should take an analyst straight there rather than showing a holding page.
export default function Home() {
  redirect("/dashboard");
}
