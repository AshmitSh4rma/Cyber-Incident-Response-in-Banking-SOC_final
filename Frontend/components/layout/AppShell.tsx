import Sidebar from "@/components/layout/Sidebar";
import Topbar from "@/components/layout/Topbar";
import ClickSpark from "@/components/ui/ClickSpark";

/**
 * Application frame: persistent left navigation, a context bar, and the page.
 */
export default function AppShell({ children }: { children: React.ReactNode }) {
  return (
    <ClickSpark
      sparkColor="#22c55e"
      sparkSize={12}
      sparkRadius={20}
      sparkCount={8}
      duration={450}
    >
      <div className="flex min-h-screen">
        <Sidebar />
        <div className="flex min-w-0 flex-1 flex-col">
          <Topbar />
          <main className="flex-1 p-4 md:p-6">{children}</main>
        </div>
      </div>
    </ClickSpark>
  );
}
