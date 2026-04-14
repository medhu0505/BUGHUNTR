import { Activity, Search, AlertTriangle, ShieldAlert, ShieldCheck, Info } from "lucide-react";
import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";
import { StatsCard } from "@/components/StatsCard";
import { SeverityBadge } from "@/components/SeverityBadge";
import { fetchActivityFeed, fetchFindings, fetchModules, fetchStats } from "@/lib/data-service";

export default function DashboardOverview() {
  const { data: stats } = useQuery({ queryKey: ["stats"], queryFn: fetchStats });
  const { data: findings = [] } = useQuery({ queryKey: ["findings"], queryFn: fetchFindings });
  const { data: activityFeed = [] } = useQuery({ queryKey: ["activity-feed"], queryFn: fetchActivityFeed });
  const { data: modules = [] } = useQuery({ queryKey: ["modules"], queryFn: fetchModules });

  const pieData = useMemo(() => {
    if (!stats) return [];
    return [
      { name: "Critical", value: stats.critical, color: "hsl(0, 85%, 55%)" },
      { name: "High", value: stats.high, color: "hsl(35, 100%, 55%)" },
      { name: "Medium", value: stats.medium, color: "hsl(280, 100%, 65%)" },
      { name: "Low", value: stats.low, color: "hsl(185, 100%, 45%)" },
    ];
  }, [stats]);

  const barData = useMemo(
    () =>
      modules
        .map((m) => ({
          name: m.name.split(" ")[0],
          count: findings.filter((f) => f.module === m.id).length,
        }))
        .filter((d) => d.count > 0),
    [findings, modules],
  );

  if (!stats) {
    return <div className="text-sm text-muted-foreground">Loading dashboard...</div>;
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold neon-text tracking-wider">DASHBOARD OVERVIEW</h1>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        <StatsCard title="Total Scans" value={stats.totalScans} icon={Search} />
        <StatsCard title="Findings" value={stats.totalFindings} icon={Activity} />
        <StatsCard title="Critical" value={stats.critical} icon={ShieldAlert} variant="critical" />
        <StatsCard title="High" value={stats.high} icon={AlertTriangle} variant="high" />
        <StatsCard title="Medium" value={stats.medium} icon={ShieldCheck} variant="medium" />
        <StatsCard title="Low" value={stats.low} icon={Info} variant="low" />
      </div>

      <div className="grid lg:grid-cols-3 gap-4">
        {/* Activity Feed */}
        <div className="lg:col-span-1 terminal-bg rounded-lg border border-border neon-border overflow-hidden">
          <div className="px-3 py-2 border-b border-border bg-muted/30">
            <span className="text-xs text-muted-foreground uppercase tracking-wider">Live Activity Feed</span>
          </div>
          <div className="p-3 h-64 overflow-y-auto font-mono text-xs leading-loose scanline">
            {activityFeed.map((entry, i) => (
              <div key={i} className={
                entry.type === 'critical' ? 'text-destructive' :
                entry.type === 'high' ? 'text-warning' :
                entry.type === 'medium' ? 'text-accent' :
                'text-foreground'
              }>
                <span className="text-muted-foreground">{entry.time}</span> {entry.msg}
              </div>
            ))}
            <span className="text-primary animate-terminal-blink">▊</span>
          </div>
        </div>

        {/* Pie Chart */}
        <div className="bg-card rounded-lg border border-border neon-border p-4">
          <p className="text-xs text-muted-foreground uppercase tracking-wider mb-2">Findings by Severity</p>
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie data={pieData} cx="50%" cy="50%" outerRadius={80} innerRadius={40} dataKey="value" strokeWidth={0}>
                {pieData.map((entry, i) => (
                  <Cell key={i} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{ background: 'hsl(220, 18%, 10%)', border: '1px solid hsl(160, 40%, 20%)', borderRadius: 6, fontFamily: 'JetBrains Mono', fontSize: 12 }}
                itemStyle={{ color: 'hsl(160, 80%, 80%)' }}
              />
            </PieChart>
          </ResponsiveContainer>
          <div className="flex justify-center gap-4 mt-2">
            {pieData.map(d => (
              <div key={d.name} className="flex items-center gap-1 text-xs">
                <div className="h-2 w-2 rounded-full" style={{ background: d.color }} />
                <span className="text-muted-foreground">{d.name}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Bar Chart */}
        <div className="bg-card rounded-lg border border-border neon-border p-4">
          <p className="text-xs text-muted-foreground uppercase tracking-wider mb-2">Findings by Module</p>
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={barData}>
              <XAxis dataKey="name" tick={{ fontSize: 10, fill: 'hsl(160, 20%, 55%)' }} />
              <YAxis tick={{ fontSize: 10, fill: 'hsl(160, 20%, 55%)' }} allowDecimals={false} />
              <Tooltip
                contentStyle={{ background: 'hsl(220, 18%, 10%)', border: '1px solid hsl(160, 40%, 20%)', borderRadius: 6, fontFamily: 'JetBrains Mono', fontSize: 12 }}
                itemStyle={{ color: 'hsl(160, 80%, 80%)' }}
              />
              <Bar dataKey="count" fill="hsl(160, 100%, 45%)" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Recent Findings Table */}
      <div className="bg-card rounded-lg border border-border neon-border overflow-hidden">
        <div className="px-4 py-3 border-b border-border bg-muted/30">
          <span className="text-xs text-muted-foreground uppercase tracking-wider">Recent Findings</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border text-muted-foreground">
                <th className="px-4 py-2 text-left">Asset</th>
                <th className="px-4 py-2 text-left">Finding</th>
                <th className="px-4 py-2 text-left">Severity</th>
                <th className="px-4 py-2 text-left">Module</th>
                <th className="px-4 py-2 text-left">Time</th>
              </tr>
            </thead>
            <tbody>
              {findings.slice(0, 8).map((f) => (
                <tr key={f.id} className="border-b border-border/50 hover:bg-muted/20 transition-colors">
                  <td className="px-4 py-2 text-secondary">{f.asset}</td>
                  <td className="px-4 py-2">{f.finding}</td>
                  <td className="px-4 py-2"><SeverityBadge severity={f.severity} /></td>
                  <td className="px-4 py-2 text-muted-foreground">{f.module}</td>
                  <td className="px-4 py-2 text-muted-foreground">{new Date(f.timestamp).toLocaleTimeString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
