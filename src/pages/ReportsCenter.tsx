import { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { toast } from "sonner";
import { Download, Copy, ChevronDown, ChevronRight, Filter } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { SeverityBadge } from "@/components/SeverityBadge";
import { H1_REPORT_TEMPLATE, type Finding, type Severity } from "@/lib/mock-data";
import { fetchFindings, fetchModules } from "@/lib/data-service";

export default function ReportsCenter() {
  const { data: allFindings = [] } = useQuery({ queryKey: ["findings"], queryFn: fetchFindings });
  const { data: modules = [] } = useQuery({ queryKey: ["modules"], queryFn: fetchModules });
  const [severityFilter, setSeverityFilter] = useState<Severity | 'all'>('all');
  const [moduleFilter, setModuleFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [search, setSearch] = useState('');
  const [expanded, setExpanded] = useState<string | null>(null);

  const filtered = useMemo(() => {
    return allFindings.filter(f => {
      if (severityFilter !== 'all' && f.severity !== severityFilter) return false;
      if (moduleFilter !== 'all' && f.module !== moduleFilter) return false;
      if (statusFilter !== 'all' && f.status !== statusFilter) return false;
      if (search && !f.asset.toLowerCase().includes(search.toLowerCase()) && !f.finding.toLowerCase().includes(search.toLowerCase())) return false;
      return true;
    });
  }, [allFindings, severityFilter, moduleFilter, statusFilter, search]);

  const copyReport = async (finding: Finding) => {
    try {
      await navigator.clipboard.writeText(H1_REPORT_TEMPLATE(finding));
      toast.success('H1 report template copied to clipboard');
    } catch {
      toast.error("Unable to copy report. Please copy it manually.");
    }
  };

  const bulkExport = () => {
    const blob = new Blob([JSON.stringify(filtered, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'bug-bounty-report.json';
    a.click();
    URL.revokeObjectURL(url);
    toast.success(`Exported ${filtered.length} findings`);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold neon-text tracking-wider">REPORTS CENTER</h1>
        <Button onClick={bulkExport} className="bg-primary text-primary-foreground hover:bg-primary/80 font-mono gap-2 text-xs">
          <Download className="h-4 w-4" /> BULK EXPORT
        </Button>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3 items-center">
        <Filter className="h-4 w-4 text-muted-foreground" />
        <Input
          placeholder="Search..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          className="w-48 bg-input border-border font-mono text-xs"
        />
        <select
          value={severityFilter}
          onChange={e => setSeverityFilter(e.target.value as Severity | 'all')}
          className="bg-input border border-border rounded px-2 py-1.5 text-xs font-mono text-foreground"
        >
          <option value="all">All Severity</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>
        <select
          value={moduleFilter}
          onChange={e => setModuleFilter(e.target.value)}
          className="bg-input border border-border rounded px-2 py-1.5 text-xs font-mono text-foreground"
        >
          <option value="all">All Modules</option>
          {modules.map(m => <option key={m.id} value={m.id}>{m.name}</option>)}
        </select>
        <select
          value={statusFilter}
          onChange={e => setStatusFilter(e.target.value)}
          className="bg-input border border-border rounded px-2 py-1.5 text-xs font-mono text-foreground"
        >
          <option value="all">All Status</option>
          <option value="open">Open</option>
          <option value="confirmed">Confirmed</option>
          <option value="false-positive">False Positive</option>
          <option value="resolved">Resolved</option>
        </select>
        <span className="text-xs text-muted-foreground ml-auto">{filtered.length} findings</span>
      </div>

      {/* Findings List */}
      <div className="bg-card rounded-lg border border-border neon-border overflow-hidden">
        {filtered.map(f => (
          <div key={f.id} className="border-b border-border/50">
            <button
              type="button"
              className="flex w-full items-center gap-4 px-4 py-3 text-left hover:bg-muted/20 transition-colors"
              onClick={() => setExpanded(expanded === f.id ? null : f.id)}
              aria-expanded={expanded === f.id}
              aria-controls={`finding-details-${f.id}`}
            >
              {expanded === f.id ? <ChevronDown className="h-4 w-4 text-primary shrink-0" /> : <ChevronRight className="h-4 w-4 text-muted-foreground shrink-0" />}
              <SeverityBadge severity={f.severity} />
              <span className="text-sm text-secondary shrink-0">{f.asset}</span>
              <span className="text-sm truncate flex-1">{f.finding}</span>
              <span className="text-xs text-muted-foreground shrink-0">{f.module}</span>
              <span className="text-xs text-muted-foreground uppercase shrink-0">{f.status}</span>
            </button>
            {expanded === f.id && (
              <div id={`finding-details-${f.id}`} className="px-4 pb-4 pl-12 space-y-3 terminal-bg border-t border-border/30">
                <div className="pt-3">
                  <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Details</p>
                  <p className="text-sm">{f.details}</p>
                </div>
                <div className="flex gap-2">
                  <Button size="sm" variant="outline" onClick={() => copyReport(f)} className="text-xs font-mono gap-1 border-border hover:bg-muted">
                    <Copy className="h-3 w-3" /> Copy H1 Report
                  </Button>
                </div>
              </div>
            )}
          </div>
        ))}
        {filtered.length === 0 && (
          <div className="p-8 text-center text-muted-foreground text-sm">No findings match your filters.</div>
        )}
      </div>
    </div>
  );
}
