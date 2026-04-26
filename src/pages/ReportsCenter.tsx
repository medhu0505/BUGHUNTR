import { useState, useMemo } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Download, Copy, ChevronDown, ChevronRight, Filter, Upload } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { SeverityBadge } from "@/components/SeverityBadge";
import { H1_REPORT_TEMPLATE, type Finding, type Severity } from "@/lib/mock-data";
import { fetchFindings, fetchModules, importBurpJson } from "@/lib/data-service";

export default function ReportsCenter() {
  const queryClient = useQueryClient();
  const { data: allFindings = [] } = useQuery({ queryKey: ["findings"], queryFn: fetchFindings });
  const { data: modules = [] } = useQuery({ queryKey: ["modules"], queryFn: fetchModules });
  const [severityFilter, setSeverityFilter] = useState<Severity | 'all'>('all');
  const [moduleFilter, setModuleFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [search, setSearch] = useState('');
  const [expanded, setExpanded] = useState<string | null>(null);
  const [importing, setImporting] = useState(false);

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

  const handleBurpImport = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    
    if (!file.name.toLowerCase().endsWith('.json')) {
      toast.error('Please select a JSON file');
      return;
    }
    
    setImporting(true);
    try {
      const result = await importBurpJson(file);
      toast.success(result.message);
      queryClient.invalidateQueries({ queryKey: ["findings"] });
      queryClient.invalidateQueries({ queryKey: ["stats"] });
    } catch (error) {
      toast.error('Failed to import Burp JSON');
      console.error(error);
    } finally {
      setImporting(false);
      event.target.value = ''; // Reset file input
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold neon-text tracking-wider">REPORTS CENTER</h1>
        <div className="flex gap-2">
          <Button asChild disabled={importing} className="bg-secondary text-secondary-foreground hover:bg-secondary/80 font-mono gap-2 text-xs">
            <label>
              <Upload className="h-4 w-4" />
              {importing ? 'IMPORTING...' : 'IMPORT BURP JSON'}
              <input
                type="file"
                accept=".json"
                onChange={handleBurpImport}
                className="hidden"
                disabled={importing}
              />
            </label>
          </Button>
          <Button onClick={bulkExport} disabled={filtered.length === 0} className="bg-primary text-primary-foreground hover:bg-primary/80 font-mono gap-2 text-xs">
            <Download className="h-4 w-4" /> BULK EXPORT
          </Button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3 items-center">
        <Filter className="h-4 w-4 text-muted-foreground" />
        <Input
          placeholder="Search..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          aria-label="Search findings"
          className="w-48 bg-input border-border font-mono text-xs"
        />
        <select
          value={severityFilter}
          onChange={e => setSeverityFilter(e.target.value as Severity | 'all')}
          aria-label="Filter by severity"
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
          aria-label="Filter by module"
          className="bg-input border border-border rounded px-2 py-1.5 text-xs font-mono text-foreground"
        >
          <option value="all">All Modules</option>
          {modules.map(m => <option key={m.id} value={m.id}>{m.name}</option>)}
        </select>
        <select
          value={statusFilter}
          onChange={e => setStatusFilter(e.target.value)}
          aria-label="Filter by status"
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
                {f.vulnerableObjects && f.vulnerableObjects.length > 0 && (
                  <div>
                    <p className="text-xs text-muted-foreground uppercase tracking-wider mb-2">Vulnerable Objects</p>
                    <div className="space-y-2">
                      {f.vulnerableObjects.map((obj, idx) => (
                        <div key={idx} className="bg-muted/30 rounded px-3 py-2 space-y-1">
                          <div className="flex items-start gap-2">
                            <span className="text-xs font-mono bg-primary/20 text-primary px-2 py-1 rounded whitespace-nowrap">{obj.type}</span>
                            <code className="text-xs text-secondary break-all flex-1">{obj.url}</code>
                          </div>
                          {obj.description && (
                            <p className="text-xs text-muted-foreground pl-2">{obj.description}</p>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
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
