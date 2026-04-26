import { useState, useMemo } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { format } from "date-fns";
import { Clock, Target, FileText, AlertCircle, Trash2 } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Checkbox } from "@/components/ui/checkbox";
import { apiRequest } from "@/lib/api-client";
import { clearScanHistory } from "@/lib/data-service";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";

interface ScanHistoryEntry {
  scanId: string;
  module: string;
  target: string;
  status: 'running' | 'complete' | 'failed';
  startTime: string;
  endTime?: string;
  totalFindings: number;
  criticalCount: number;
  highCount: number;
}

async function fetchScanHistory(): Promise<ScanHistoryEntry[]> {
  return apiRequest<ScanHistoryEntry[]>("/scans");
}

async function deleteScans(scanIds: string[]): Promise<{ deleted: number }> {
  return apiRequest<{ deleted: number }>("/scans/delete", {
    method: "POST",
    body: JSON.stringify({ scanIds }),
  });
}

export default function ScanHistoryPage() {
  const queryClient = useQueryClient();
  const { data: scans = [] } = useQuery({
    queryKey: ["scan-history"],
    queryFn: fetchScanHistory,
    refetchInterval: 30000,
    retry: 1,
  });

  const [search, setSearch] = useState("");
  const [moduleFilter, setModuleFilter] = useState<string>("all");
  const [selectedScans, setSelectedScans] = useState<Set<string>>(new Set());
  const [isDeleting, setIsDeleting] = useState(false);

  const onClearHistory = async () => {
    if (!window.confirm("Delete ALL scans permanently? This cannot be undone.")) return;
    try {
      const result = await clearScanHistory();
      toast.success(`Cleared ${result.removedScans} scans`);
      setSelectedScans(new Set());
      queryClient.invalidateQueries({ queryKey: ["scan-history"] });
      queryClient.invalidateQueries({ queryKey: ["findings"] });
      queryClient.invalidateQueries({ queryKey: ["stats"] });
      queryClient.invalidateQueries({ queryKey: ["activity-feed"] });
    } catch {
      toast.error("Failed to clear scan history");
    }
  };

  const onDeleteSelected = async () => {
    if (selectedScans.size === 0) {
      toast.error("No scans selected");
      return;
    }
    if (!window.confirm(`Delete ${selectedScans.size} selected scan(s)? This cannot be undone.`)) return;
    
    try {
      setIsDeleting(true);
      const result = await deleteScans(Array.from(selectedScans));
      toast.success(`Deleted ${result.deleted} scan(s)`);
      setSelectedScans(new Set());
      queryClient.invalidateQueries({ queryKey: ["scan-history"] });
      queryClient.invalidateQueries({ queryKey: ["findings"] });
      queryClient.invalidateQueries({ queryKey: ["stats"] });
      queryClient.invalidateQueries({ queryKey: ["activity-feed"] });
    } catch {
      toast.error("Failed to delete selected scans");
    } finally {
      setIsDeleting(false);
    }
  };

  const toggleScanSelection = (scanId: string) => {
    const newSelected = new Set(selectedScans);
    if (newSelected.has(scanId)) {
      newSelected.delete(scanId);
    } else {
      newSelected.add(scanId);
    }
    setSelectedScans(newSelected);
  };

  const toggleSelectAll = () => {
    if (selectedScans.size === filtered.length) {
      setSelectedScans(new Set());
    } else {
      setSelectedScans(new Set(filtered.map(s => s.scanId)));
    }
  };

  const filtered = useMemo(() => {
    return scans.filter((scan) => {
      if (search && !scan.target.toLowerCase().includes(search.toLowerCase())) return false;
      if (moduleFilter !== "all" && scan.module !== moduleFilter) return false;
      return true;
    });
  }, [scans, search, moduleFilter]);

  const uniqueModules = Array.from(new Set(scans.map((s) => s.module))).sort();

  const calculateDuration = (start: string, end?: string): string => {
    if (!end) return "In progress...";
    const startTime = new Date(start).getTime();
    const endTime = new Date(end).getTime();
    const seconds = Math.floor((endTime - startTime) / 1000);
    if (seconds < 60) return `${seconds}s`;
    const minutes = Math.floor(seconds / 60);
    return `${minutes}m ${seconds % 60}s`;
  };

  const getStatusColor = (status: string) => {
    if (status === "complete") return "text-primary";
    if (status === "running") return "text-warning animate-pulse";
    return "text-destructive";
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold neon-text tracking-wider">SCAN HISTORY</h1>
          <p className="text-sm text-muted-foreground mt-1">Manage and review all your security scans</p>
        </div>
        <div className="flex items-center gap-2 flex-wrap justify-end">
          <span className="text-xs text-muted-foreground font-mono px-3 py-2 rounded bg-muted">
            {filtered.length} scans
          </span>
          {selectedScans.size > 0 && (
            <Button 
              size="sm" 
              variant="destructive" 
              onClick={onDeleteSelected}
              disabled={isDeleting}
              className="text-xs font-mono gap-2"
            >
              <Trash2 className="h-3 w-3" />
              DELETE {selectedScans.size}
            </Button>
          )}
          <Button size="sm" variant="outline" onClick={onClearHistory} className="text-xs font-mono">
            CLEAR ALL
          </Button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3 items-center">
        <Target className="h-4 w-4 text-muted-foreground" />
        <Input
          placeholder="Search by target domain..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          aria-label="Search scans by target"
          className="flex-1 max-w-xs bg-input border-border font-mono text-xs"
        />
        <select
          value={moduleFilter}
          onChange={(e) => setModuleFilter(e.target.value)}
          aria-label="Filter by module"
          className="bg-input border border-border rounded px-2 py-1.5 text-xs font-mono text-foreground"
        >
          <option value="all">All Modules</option>
          {uniqueModules.map((mod) => (
            <option key={mod} value={mod}>
              {mod.replace(/-/g, " ").toUpperCase()}
            </option>
          ))}
        </select>
        {search && (
          <button
            onClick={() => setSearch("")}
            className="text-xs text-muted-foreground hover:text-foreground transition-colors"
          >
            Clear
          </button>
        )}
      </div>

      {/* Scan List */}
      <div className="bg-card rounded-lg border border-border neon-border overflow-hidden">
        {filtered.length === 0 ? (
          <div className="p-8 text-center text-muted-foreground text-sm">
            {scans.length === 0 ? "No scans yet. Start by running a security scan." : "No scans match your filters."}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border text-muted-foreground bg-muted/30">
                  <th className="px-4 py-3 text-left font-semibold w-8">
                    <Checkbox
                      checked={selectedScans.size === filtered.length && filtered.length > 0}
                      onCheckedChange={toggleSelectAll}
                      aria-label="Select all scans"
                    />
                  </th>
                  <th className="px-4 py-3 text-left font-semibold">Timestamp</th>
                  <th className="px-4 py-3 text-left font-semibold">Module</th>
                  <th className="px-4 py-3 text-left font-semibold">Target</th>
                  <th className="px-4 py-3 text-left font-semibold">Duration</th>
                  <th className="px-4 py-3 text-center font-semibold">Findings</th>
                  <th className="px-4 py-3 text-center font-semibold">Critical</th>
                  <th className="px-4 py-3 text-left font-semibold">Status</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((scan) => (
                  <tr
                    key={scan.scanId}
                    className={`border-b border-border/50 transition-colors ${
                      selectedScans.has(scan.scanId)
                        ? "bg-primary/10 hover:bg-primary/15"
                        : "hover:bg-muted/20"
                    }`}
                  >
                    <td className="px-4 py-3">
                      <Checkbox
                        checked={selectedScans.has(scan.scanId)}
                        onCheckedChange={() => toggleScanSelection(scan.scanId)}
                        aria-label={`Select ${scan.target}`}
                      />
                    </td>
                    <td className="px-4 py-3 text-muted-foreground font-mono">
                      <div className="flex items-center gap-1">
                        <Clock className="h-3 w-3" />
                        <time>{format(new Date(scan.startTime), "MMM dd HH:mm")}</time>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-secondary font-mono uppercase text-xs">
                      {scan.module.replace(/-/g, " ")}
                    </td>
                    <td className="px-4 py-3 max-w-xs">
                      <div className="flex items-center gap-1">
                        <Target className="h-3 w-3 text-muted-foreground shrink-0" />
                        <span className="truncate text-xs">{scan.target}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-muted-foreground font-mono text-xs">
                      {calculateDuration(scan.startTime, scan.endTime)}
                    </td>
                    <td className="px-4 py-3 text-center">
                      <span className="inline-flex items-center justify-center gap-1 bg-muted px-2 py-1 rounded text-xs font-semibold">
                        <FileText className="h-3 w-3" />
                        {scan.totalFindings}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-center">
                      {scan.criticalCount > 0 ? (
                        <span className="inline-flex items-center justify-center gap-1 bg-destructive/10 px-2 py-1 rounded text-xs font-bold text-destructive">
                          <AlertCircle className="h-3 w-3" />
                          {scan.criticalCount}
                        </span>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <span className={`font-mono uppercase text-xs font-semibold ${getStatusColor(scan.status)}`}>
                        {scan.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Summary Stats */}
      {filtered.length > 0 && (
        <div className="grid md:grid-cols-4 gap-4">
          <div className="bg-card rounded-lg border border-border p-4 hover:border-primary/50 transition-colors">
            <p className="text-xs text-muted-foreground uppercase tracking-wider mb-2">Total Scans</p>
            <p className="text-3xl font-bold neon-text">{filtered.length}</p>
          </div>
          <div className="bg-card rounded-lg border border-border p-4 hover:border-primary/50 transition-colors">
            <p className="text-xs text-muted-foreground uppercase tracking-wider mb-2">Total Findings</p>
            <p className="text-3xl font-bold text-foreground">
              {filtered.reduce((acc, scan) => acc + scan.totalFindings, 0)}
            </p>
          </div>
          <div className="bg-card rounded-lg border border-border p-4 hover:border-primary/50 transition-colors">
            <p className="text-xs text-muted-foreground uppercase tracking-wider mb-2">Critical Issues</p>
            <p className="text-3xl font-bold text-destructive">
              {filtered.reduce((acc, scan) => acc + scan.criticalCount, 0)}
            </p>
          </div>
          <div className="bg-card rounded-lg border border-border p-4 hover:border-primary/50 transition-colors">
            <p className="text-xs text-muted-foreground uppercase tracking-wider mb-2">Avg Duration</p>
            <p className="text-2xl font-bold text-primary">
              {Math.round(filtered.reduce((acc, scan) => {
                if (!scan.endTime) return acc;
                const duration = (new Date(scan.endTime).getTime() - new Date(scan.startTime).getTime()) / 1000;
                return acc + duration;
              }, 0) / filtered.length)}s
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
