import { useState, useCallback, useRef } from "react";
import { useQuery } from "@tanstack/react-query";
import { useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Play, Download, AlertCircle, CheckCircle, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { SeverityBadge } from "@/components/SeverityBadge";
import { runScan as runScanRequest, fetchModules } from "@/lib/data-service";
import { MODULES, type Finding } from "@/lib/mock-data";

interface ScanProgress {
  moduleId: string;
  moduleName: string;
  status: 'pending' | 'running' | 'complete' | 'error';
  findingsCount?: number;
  error?: string;
}

const MAX_CONCURRENT_SCANS = 3; // Run 3 modules in parallel for efficiency
const SCAN_TIMEOUT = 30000; // 30 seconds timeout per module for scan all

export default function ScanAllPage() {
  const queryClient = useQueryClient();
  const { data: fetchedModules } = useQuery({ queryKey: ["modules"], queryFn: fetchModules });
  const modules = fetchedModules && fetchedModules.length > 0 ? fetchedModules : MODULES;
  const [target, setTarget] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState<ScanProgress[]>([]);
  const [allFindings, setAllFindings] = useState<Finding[]>([]);
  const abortControllerRef = useRef<AbortController | null>(null);

  const runAllScans = useCallback(async () => {
    if (!target.trim()) {
      toast.error('Please enter a target');
      return;
    }

    // Initialize progress for all modules
    const initialProgress: ScanProgress[] = modules.map(m => ({
      moduleId: m.id,
      moduleName: m.name,
      status: 'pending',
    }));
    setScanProgress(initialProgress);
    setAllFindings([]);
    setIsScanning(true);
    abortControllerRef.current = new AbortController();

    const collectedFindings: Finding[] = [];
    let completedCount = 0;
    let errorCount = 0;

    try {
      // Run scans in parallel batches (MAX_CONCURRENT_SCANS at a time)
      for (let i = 0; i < modules.length; i += MAX_CONCURRENT_SCANS) {
        if (abortControllerRef.current.signal.aborted) break;

        const batch = modules.slice(i, i + MAX_CONCURRENT_SCANS);
        
        // Run batch concurrently
        await Promise.all(
          batch.map(async (module) => {
            try {
              // Update progress to "running"
              setScanProgress(prev => prev.map(p => 
                p.moduleId === module.id ? { ...p, status: 'running' } : p
              ));

              // Create timeout promise
              const scanPromise = runScanRequest(module.id, target);
              const timeoutPromise = new Promise<never>((_, reject) =>
                setTimeout(() => reject(new Error('Scan timeout')), SCAN_TIMEOUT)
              );

              const findings = await Promise.race([scanPromise, timeoutPromise]);
              collectedFindings.push(...findings);
              completedCount++;

              // Update progress to "complete"
              setScanProgress(prev => prev.map(p => 
                p.moduleId === module.id 
                  ? { ...p, status: 'complete', findingsCount: findings.filter(f => f.severity !== 'info').length } 
                  : p
              ));
            } catch (error) {
              errorCount++;
              const message = error instanceof Error ? error.message : "Scan failed";
              setScanProgress(prev => prev.map(p => 
                p.moduleId === module.id 
                  ? { ...p, status: 'error', error: message } 
                  : p
              ));
            }
          })
        );
      }

      setAllFindings(collectedFindings);

      const severityBreakdown = {
        critical: collectedFindings.filter(f => f.severity === 'critical').length,
        high: collectedFindings.filter(f => f.severity === 'high').length,
        medium: collectedFindings.filter(f => f.severity === 'medium').length,
        low: collectedFindings.filter(f => f.severity === 'low').length,
      };

      if (errorCount > 0) {
        toast.error(`Scan completed with ${errorCount} module error(s).`, {
          description: `Completed: ${completedCount}/${initialProgress.length} • Findings: ${collectedFindings.length}`,
        });
      } else {
        toast.success(`Scan complete! ${collectedFindings.length} total findings found.`, {
          description: `Critical: ${severityBreakdown.critical}, High: ${severityBreakdown.high}`,
        });
      }

      queryClient.invalidateQueries({ queryKey: ["findings"] });
      queryClient.invalidateQueries({ queryKey: ["stats"] });
    } finally {
      setIsScanning(false);
      abortControllerRef.current = null;
    }
  }, [modules, target, queryClient]);

  const stopScans = useCallback(() => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      setIsScanning(false);
      toast.info("Scan aborted");
    }
  }, []);

  const exportAllResults = () => {
    const blob = new Blob([JSON.stringify(allFindings, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `scan-all-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success('Exported all findings');
  };

  const exportCSV = () => {
    const csv = [
      'Module,Asset,Finding,Severity,Status,VulnerableObjects',
      ...allFindings.map(f => {
        const vulnObjs = f.vulnerableObjects?.map(v => v.url).join('; ') || '';
        return `"${f.module}","${f.asset}","${f.finding}","${f.severity}","${f.status}","${vulnObjs}"`;
      })
    ].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `scan-all-${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success('Exported as CSV');
  };

  const findingsBySeverity = {
    critical: allFindings.filter(f => f.severity === 'critical').length,
    high: allFindings.filter(f => f.severity === 'high').length,
    medium: allFindings.filter(f => f.severity === 'medium').length,
    low: allFindings.filter(f => f.severity === 'low').length,
    info: allFindings.filter(f => f.severity === 'info').length,
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold neon-text tracking-wider">SCAN ALL MODULES</h1>
        <p className="text-sm text-muted-foreground mt-1">Run all available security scanners on a single target</p>
      </div>

      {/* Input Section */}
      <div className="bg-card rounded-lg border border-border neon-border p-4 space-y-4">
        <div>
          <label className="text-xs text-muted-foreground uppercase tracking-wider block mb-2">Target Domain</label>
          <div className="flex gap-2">
            <Input
              placeholder="Enter target domain or URL (e.g., example.com)"
              value={target}
              onChange={e => setTarget(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !isScanning && target.trim()) {
                  runAllScans();
                }
              }}
              disabled={isScanning}
              className="bg-input border-border font-mono text-sm placeholder:text-muted-foreground"
            />
            {isScanning ? (
              <Button
                onClick={stopScans}
                variant="destructive"
                className="font-mono gap-2 whitespace-nowrap"
              >
                <X className="h-4 w-4" />
                STOP
              </Button>
            ) : (
              <Button
                onClick={runAllScans}
                disabled={isScanning || !target.trim()}
                className="bg-primary text-primary-foreground hover:bg-primary/80 font-mono gap-2 whitespace-nowrap"
              >
                <Play className="h-4 w-4" />
                START ALL SCANS
              </Button>
            )}
          </div>
        </div>
        <p className="text-xs text-muted-foreground">
          Running {modules.length} modules with {MAX_CONCURRENT_SCANS} parallel scans. Estimated time: 10-20 seconds.
        </p>
      </div>

      {/* Progress Section */}
      {scanProgress.length > 0 && (
        <div className="bg-card rounded-lg border border-border neon-border overflow-hidden">
          <div className="px-4 py-3 border-b border-border bg-muted/30">
            <p className="text-xs text-muted-foreground uppercase tracking-wider">Scan Progress</p>
          </div>
          <div className="divide-y divide-border">
            {scanProgress.map(progress => (
              <div key={progress.moduleId} className="px-4 py-3 flex items-center gap-3">
                <div className="flex-1">
                  <p className="text-sm font-medium">{progress.moduleName}</p>
                  <p className="text-xs text-muted-foreground">{progress.moduleId}</p>
                </div>
                <div className="flex items-center gap-2">
                  {progress.status === 'pending' && (
                    <span className="text-xs text-muted-foreground">Pending</span>
                  )}
                  {progress.status === 'running' && (
                    <span className="text-xs text-warning animate-pulse flex items-center gap-1">
                      <div className="w-2 h-2 rounded-full bg-warning animate-pulse" />
                      Scanning...
                    </span>
                  )}
                  {progress.status === 'complete' && (
                    <span className="text-xs text-primary flex items-center gap-1">
                      <CheckCircle className="h-3 w-3" />
                      {progress.findingsCount ? `${progress.findingsCount} findings` : 'Complete'}
                    </span>
                  )}
                  {progress.status === 'error' && (
                    <div className="text-right">
                      <span className="text-xs text-destructive flex items-center gap-1 justify-end">
                        <AlertCircle className="h-3 w-3" />
                        Error
                      </span>
                      {progress.error && (
                        <p className="text-[10px] text-muted-foreground max-w-72 truncate">{progress.error}</p>
                      )}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Summary Stats */}
      {allFindings.length > 0 && (
        <div>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mb-6">
            <div className="bg-destructive/10 rounded-lg border border-destructive/20 p-3 text-center">
              <p className="text-xs text-destructive uppercase tracking-wider font-bold">{findingsBySeverity.critical}</p>
              <p className="text-xs text-muted-foreground">Critical</p>
            </div>
            <div className="bg-warning/10 rounded-lg border border-warning/20 p-3 text-center">
              <p className="text-xs text-warning uppercase tracking-wider font-bold">{findingsBySeverity.high}</p>
              <p className="text-xs text-muted-foreground">High</p>
            </div>
            <div className="bg-accent/10 rounded-lg border border-accent/20 p-3 text-center">
              <p className="text-xs text-accent uppercase tracking-wider font-bold">{findingsBySeverity.medium}</p>
              <p className="text-xs text-muted-foreground">Medium</p>
            </div>
            <div className="bg-info/10 rounded-lg border border-info/20 p-3 text-center">
              <p className="text-xs text-info uppercase tracking-wider font-bold">{findingsBySeverity.low}</p>
              <p className="text-xs text-muted-foreground">Low</p>
            </div>
            <div className="bg-muted/50 rounded-lg border border-border p-3 text-center">
              <p className="text-xs font-bold uppercase tracking-wider">{allFindings.length}</p>
              <p className="text-xs text-muted-foreground">Total</p>
            </div>
          </div>

          <div className="flex gap-2 mb-6">
            <Button onClick={exportAllResults} className="bg-primary text-primary-foreground hover:bg-primary/80 font-mono gap-2 text-xs">
              <Download className="h-4 w-4" /> Export JSON
            </Button>
            <Button onClick={exportCSV} variant="outline" className="border-border font-mono gap-2 text-xs hover:bg-muted">
              <Download className="h-4 w-4" /> Export CSV
            </Button>
          </div>
        </div>
      )}

      {/* Findings Results */}
      {allFindings.length > 0 && (
        <div className="bg-card rounded-lg border border-border neon-border overflow-hidden">
          <div className="px-4 py-3 border-b border-border bg-muted/30">
            <p className="text-xs text-muted-foreground uppercase tracking-wider">
              All Findings — {allFindings.length} total
            </p>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border text-muted-foreground bg-muted/20">
                  <th className="px-4 py-2 text-left font-semibold">Module</th>
                  <th className="px-4 py-2 text-left font-semibold">Asset</th>
                  <th className="px-4 py-2 text-left font-semibold">Finding</th>
                  <th className="px-4 py-2 text-left font-semibold">Severity</th>
                  <th className="px-4 py-2 text-left font-semibold">Status</th>
                </tr>
              </thead>
              <tbody>
                {allFindings.map(f => (
                  <tr key={f.id} className="border-b border-border/50 hover:bg-muted/20 transition-colors">
                    <td className="px-4 py-2 text-secondary font-mono uppercase text-xs">{f.module.replace(/-/g, ' ')}</td>
                    <td className="px-4 py-2 text-muted-foreground">{f.asset}</td>
                    <td className="px-4 py-2">{f.finding}</td>
                    <td className="px-4 py-2"><SeverityBadge severity={f.severity} /></td>
                    <td className="px-4 py-2 text-muted-foreground uppercase text-xs">{f.status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Empty State */}
      {!isScanning && scanProgress.length === 0 && (
        <div className="bg-muted/20 rounded-lg border border-border/50 p-8 text-center">
          <p className="text-muted-foreground">Enter a target and click "START ALL SCANS" to begin comprehensive security assessment</p>
        </div>
      )}
    </div>
  );
}
