import {
  Globe, Database, Shield, FileWarning, Key, ExternalLink,
  Layers, Server, Mail, Gauge, LayoutDashboard, FileText, Bug
} from "lucide-react";
import { NavLink } from "@/components/NavLink";
import {
  Sidebar, SidebarContent, SidebarGroup, SidebarGroupContent,
  SidebarGroupLabel, SidebarMenu, SidebarMenuButton, SidebarMenuItem,
  useSidebar,
} from "@/components/ui/sidebar";
import { MODULES } from "@/lib/mock-data";

const ICON_MAP: Record<string, React.ElementType> = {
  Globe, Database, Shield, FileWarning, Key, ExternalLink, Layers, Server, Mail, Gauge
};

export function AppSidebar() {
  const { state } = useSidebar();
  const collapsed = state === "collapsed";

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
                  <NavLink to="/" end activeClassName="bg-sidebar-accent neon-text">
                    <LayoutDashboard className="mr-2 h-4 w-4" />
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
              {MODULES.map((item) => {
                const Icon = ICON_MAP[item.icon] ?? Bug;
                return (
                  <SidebarMenuItem key={item.path}>
                    <SidebarMenuButton asChild>
                      <NavLink to={item.path} activeClassName="bg-sidebar-accent neon-text">
                        <Icon className="mr-2 h-4 w-4" />
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
                  <NavLink to="/reports" activeClassName="bg-sidebar-accent neon-text">
                    <FileText className="mr-2 h-4 w-4" />
                    {!collapsed && <span>Reports Center</span>}
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
