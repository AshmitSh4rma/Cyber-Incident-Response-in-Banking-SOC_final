import Sidebar from "@/components/layout/Sidebar";
import Topbar from "@/components/layout/Topbar";

/**
 * Application frame: persistent left navigation, a context bar, and the page.
 *
 * Previously this also carried a splash screen behind a `showEntry` flag that was
 * hardcoded to false — a branch that could never run. Gone.
 */
export default function AppShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar />
        <main className="flex-1 p-4 md:p-6">{children}</main>
      </div>
    </div>
  );
}
