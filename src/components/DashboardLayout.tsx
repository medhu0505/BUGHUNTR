import { SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar";
import { AppSidebar } from "@/components/AppSidebar";

export function DashboardLayout({ children }: { children: React.ReactNode }) {
  return (
    <SidebarProvider>
      <div className="min-h-screen flex w-full">
        <AppSidebar />
        <div className="flex-1 flex flex-col min-w-0">
          <header className="h-12 flex items-center border-b border-border px-4 bg-card/50">
            <SidebarTrigger className="text-muted-foreground hover:text-primary" />
            <div className="ml-auto flex items-center gap-2">
              <span className="text-xs text-muted-foreground">v1.0.0</span>
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
