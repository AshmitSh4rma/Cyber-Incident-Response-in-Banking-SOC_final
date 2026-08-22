import Sidebar from "@/components/layout/Sidebar";
import Topbar from "@/components/layout/Topbar";
import { DetailProvider } from "@/lib/detail";

/**
 * Application frame: persistent navigation, a context bar, and the page.
 *
 * DetailProvider sits here so the overview/analyst choice is one setting for the
 * whole console rather than per screen.
 */
export default function AppShell({ children }: { children: React.ReactNode }) {
  return (
    <DetailProvider>
      <div className="flex min-h-screen">
        <Sidebar />
        <div className="flex min-w-0 flex-1 flex-col">
          <Topbar />
          <main className="flex-1 p-4 md:p-6">{children}</main>
        </div>
      </div>
    </DetailProvider>
  );
}
