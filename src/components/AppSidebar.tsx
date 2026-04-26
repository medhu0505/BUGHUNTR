import {
  Globe, Database, Shield, FileWarning, Key, ExternalLink,
  Layers, Server, Mail, Gauge, LayoutDashboard, FileText, Bug, History, Info, Zap
} from "lucide-react";
import { NavLink } from "@/components/NavLink";
import {
  Sidebar, SidebarContent, SidebarGroup, SidebarGroupContent,
  SidebarGroupLabel, SidebarMenu, SidebarMenuButton, SidebarMenuItem,
  useSidebar,
} from "@/components/ui/sidebar";
import { useQuery } from "@tanstack/react-query";
import { fetchModules } from "@/lib/data-service";
import { MODULES } from "@/lib/mock-data";

const ICON_MAP: Record<string, React.ElementType> = {
  Globe, Database, Shield, FileWarning, Key, ExternalLink, Layers, Server, Mail, Gauge
};

export function AppSidebar() {
  const { state } = useSidebar();
  const collapsed = state === "collapsed";
  const { data: dynamicModules } = useQuery({ queryKey: ["modules"], queryFn: fetchModules });
  const modules = dynamicModules && dynamicModules.length > 0 ? dynamicModules : MODULES;

  return (
    <Sidebar collapsible="icon" className="border-r border-border">
      <SidebarContent className="py-4">
        {/* Brand */}
        {!collapsed && (
          <div className="px-4 pb-4 flex items-center gap-2">
            <Bug className="h-6 w-6 text-primary" />
            <span className="text-lg font-bold neon-text tracking-wider">BUGHUNTR</span>
          </div>
        )}
        {collapsed && (
          <div className="flex justify-center pb-4">
            <Bug className="h-6 w-6 text-primary" />
          </div>
        )}

        <SidebarGroup>
          <SidebarGroupLabel className="text-muted-foreground text-xs uppercase tracking-widest">Main</SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              <SidebarMenuItem>
                <SidebarMenuButton asChild>
                  <NavLink to="/" end className="flex items-center gap-2" activeClassName="bg-sidebar-accent text-sidebar-accent-foreground font-semibold">
                    <LayoutDashboard className="h-4 w-4 shrink-0" />
                    {!collapsed && <span>Dashboard</span>}
                  </NavLink>
                </SidebarMenuButton>
              </SidebarMenuItem>
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>

        <SidebarGroup>
          <SidebarGroupLabel className="text-muted-foreground text-xs uppercase tracking-widest">Scanners</SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              <SidebarMenuItem>
                <SidebarMenuButton asChild>
                  <NavLink to="/scan-all" end className="flex items-center gap-2" activeClassName="bg-sidebar-accent text-sidebar-accent-foreground font-semibold">
                    <Zap className="h-4 w-4 shrink-0" />
                    {!collapsed && <span className="text-primary">Scan All</span>}
                  </NavLink>
                </SidebarMenuButton>
              </SidebarMenuItem>
              {modules.map((item) => {
                const Icon = ICON_MAP[item.icon] ?? Bug;
                return (
                  <SidebarMenuItem key={item.path}>
                    <SidebarMenuButton asChild>
                      <NavLink to={item.path} end className="flex items-center gap-2" activeClassName="bg-sidebar-accent text-sidebar-accent-foreground font-semibold">
                        <Icon className="h-4 w-4 shrink-0" />
                        {!collapsed && <span className="text-sm">{item.name}</span>}
                      </NavLink>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                );
              })}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>

        <SidebarGroup>
          <SidebarGroupLabel className="text-muted-foreground text-xs uppercase tracking-widest">Output</SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              <SidebarMenuItem>
                <SidebarMenuButton asChild>
                  <NavLink to="/reports" end className="flex items-center gap-2" activeClassName="bg-sidebar-accent text-sidebar-accent-foreground font-semibold">
                    <FileText className="h-4 w-4 shrink-0" />
                    {!collapsed && <span>Reports Center</span>}
                  </NavLink>
                </SidebarMenuButton>
              </SidebarMenuItem>
              <SidebarMenuItem>
                <SidebarMenuButton asChild>
                  <NavLink to="/history" end className="flex items-center gap-2" activeClassName="bg-sidebar-accent text-sidebar-accent-foreground font-semibold">
                    <History className="h-4 w-4 shrink-0" />
                    {!collapsed && <span>Scan History</span>}
                  </NavLink>
                </SidebarMenuButton>
              </SidebarMenuItem>
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>

        <SidebarGroup>
          <SidebarGroupLabel className="text-muted-foreground text-xs uppercase tracking-widest">Help</SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              <SidebarMenuItem>
                <SidebarMenuButton asChild>
                  <NavLink to="/about" end className="flex items-center gap-2" activeClassName="bg-sidebar-accent text-sidebar-accent-foreground font-semibold">
                    <Info className="h-4 w-4 shrink-0" />
                    {!collapsed && <span>About</span>}
                  </NavLink>
                </SidebarMenuButton>
              </SidebarMenuItem>
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>
    </Sidebar>
  );
}
