import Sidebar from "@/components/layout/Sidebar";
import Topbar from "@/components/layout/Topbar";
import ClickSpark from "@/components/ui/ClickSpark";
import { DetailProvider } from "@/lib/detail";

/**
 * Application frame: persistent navigation, a context bar, and the page.
 *
 * DetailProvider sits here so the overview/analyst choice is one setting for the
 * whole console rather than per screen. It stays outside ClickSpark: the spark
 * layer is decoration and removes itself under reduced motion, and the detail
 * context must not depend on whether that layer rendered.
 */
export default function AppShell({ children }: { children: React.ReactNode }) {
  return (
    <DetailProvider>
      <ClickSpark sparkSize={12} sparkRadius={20} sparkCount={8} duration={450}>
        <div className="flex min-h-screen">
          <Sidebar />
          <div className="flex min-w-0 flex-1 flex-col">
            <Topbar />
            <main className="flex-1 p-4 md:p-6">{children}</main>
          </div>
        </div>
      </ClickSpark>
    </DetailProvider>
  );
}
