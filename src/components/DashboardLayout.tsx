import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar";
import { AppSidebar } from "@/components/AppSidebar";
import { AlertCircle } from "lucide-react";

const ACTIVE_SCAN_KEY = "bbh-active-scan";

function useBackgroundScan() {
  const [activeScan, setActiveScan] = useState<{ moduleId: string; target: string; scanId: string } | null>(null);
  
  useEffect(() => {
    const checkActiveScan = () => {
      const raw = localStorage.getItem(ACTIVE_SCAN_KEY);
      if (!raw) {
        setActiveScan(null);
        return;
      }
      try {
        setActiveScan(JSON.parse(raw));
      } catch {
        setActiveScan(null);
      }
    };

    checkActiveScan();
    const interval = setInterval(checkActiveScan, 2000); // Check every 2 seconds
    return () => clearInterval(interval);
  }, []);

  return activeScan;
}

export function DashboardLayout({ children }: { children: React.ReactNode }) {
  const navigate = useNavigate();
  const activeScan = useBackgroundScan();

  return (
    <SidebarProvider>
      <div className="min-h-screen flex w-full">
        <AppSidebar />
        <div className="flex-1 flex flex-col min-w-0">
          {/* Background Scan Banner */}
          {activeScan && (
            <div className="h-10 flex items-center justify-between border-b border-warning/50 bg-warning/5 px-4">
              <div className="flex items-center gap-2">
                <AlertCircle className="h-4 w-4 text-warning animate-pulse" />
                <span className="text-xs text-warning font-semibold">
                  Scan in progress: {activeScan.target} ({activeScan.moduleId.replace(/-/g, " ")})
                </span>
              </div>
              <button
                onClick={() => navigate(`/scanner/${activeScan.moduleId}`)}
                className="text-xs text-warning hover:text-warning/80 font-mono px-2 py-1 rounded hover:bg-warning/10 transition-colors"
              >
                RESUME
              </button>
            </div>
          )}
          
          <header className="h-12 flex items-center border-b border-border px-4 bg-card/50">
            <SidebarTrigger className="text-muted-foreground hover:text-primary" />
            <div className="ml-auto flex items-center gap-2">
              <span className="text-xs text-muted-foreground">v3.2.0</span>
              <div className="h-2 w-2 rounded-full bg-primary animate-pulse-neon" />
              <span className="text-xs text-primary">ONLINE</span>
            </div>
          </header>
          <main className="flex-1 overflow-auto p-4 md:p-6">
            {children}
          </main>
        </div>
      </div>
    </SidebarProvider>
  );
}
