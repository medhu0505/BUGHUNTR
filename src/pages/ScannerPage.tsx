import { useState, useCallback, useEffect } from "react";
import { useParams } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Play, Download, Square } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Checkbox } from "@/components/ui/checkbox";
import { TerminalLog } from "@/components/TerminalLog";
import { SeverityBadge } from "@/components/SeverityBadge";
import { runScan as runScanRequest, fetchModuleConfig, fetchModules } from "@/lib/data-service";
import { type Finding, type ModuleOption, type ScanStatus } from "@/lib/mock-data";

export default function ScannerPage() {
  const queryClient = useQueryClient();
  const { moduleId } = useParams<{ moduleId: string }>();
  const { data: modules = [] } = useQuery({ queryKey: ["modules"], queryFn: fetchModules });
  const module = modules.find((m) => m.id === moduleId);
  const { data: config = [] } = useQuery({
    queryKey: ["module-config", moduleId],
    queryFn: () => fetchModuleConfig(moduleId || ""),
    enabled: Boolean(moduleId),
  });

  const [target, setTarget] = useState('');
  const [scanStatus, setScanStatus] = useState<ScanStatus>('idle');
  const [results, setResults] = useState<Finding[]>([]);
  const [options, setOptions] = useState<Record<string, boolean>>({});

  const ensureDefaultOptions = useCallback((moduleConfig: ModuleOption[]) => {
    setOptions((prev) => {
      const next = { ...prev };
      for (const item of moduleConfig) {
        if (next[item.label] === undefined) {
          next[item.label] = item.default;
        }
      }
      return next;
    });
  }, []);

  useEffect(() => {
    if (config.length > 0) {
      ensureDefaultOptions(config);
    }
  }, [config, ensureDefaultOptions]);

  const runScan = useCallback(() => {
    if (!target.trim()) {
      toast.error('Please enter a target');
      return;
    }
    setScanStatus('running');
    setResults([]);
    toast('Scan started', { description: `Scanning ${target}...` });
  }, [target]);

  const onScanComplete = useCallback(() => {
    runScanRequest(moduleId || "", target)
      .then((findings) => {
        setResults(findings);
        setScanStatus("complete");
        queryClient.invalidateQueries({ queryKey: ["findings"] });
        queryClient.invalidateQueries({ queryKey: ["stats"] });
        const criticals = findings.filter((f) => f.severity === "critical").length;
        if (criticals > 0) {
          toast.error(`${criticals} critical finding(s) detected!`);
        } else {
          toast.success("Scan complete");
        }
      })
      .catch(() => {
        setScanStatus("idle");
        toast.error("Scan failed. Please try again.");
      });
  }, [moduleId, queryClient, target]);

  const exportData = (format: 'csv' | 'json') => {
    if (format === 'json') {
      const blob = new Blob([JSON.stringify(results, null, 2)], { type: 'application/json' });
      downloadBlob(blob, `${moduleId}-results.json`);
    } else {
      const csv = [
        'Asset,Finding,Severity,Status',
        ...results.map(r => `"${r.asset}","${r.finding}","${r.severity}","${r.status}"`)
      ].join('\n');
      const blob = new Blob([csv], { type: 'text/csv' });
      downloadBlob(blob, `${moduleId}-results.csv`);
    }
    toast.success(`Exported as ${format.toUpperCase()}`);
  };

  const downloadBlob = (blob: Blob, filename: string) => {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (!module) return <div className="text-destructive">Module not found</div>;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold neon-text tracking-wider">{module.name.toUpperCase()}</h1>

      {/* Target + Config */}
      <div className="grid lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 space-y-4">
          <div className="flex gap-2">
            <Input
              placeholder="Enter target domain or URL..."
              value={target}
              onChange={e => setTarget(e.target.value)}
              className="bg-input border-border font-mono text-sm placeholder:text-muted-foreground"
            />
            <Button
              onClick={runScan}
              disabled={scanStatus === 'running'}
              className="bg-primary text-primary-foreground hover:bg-primary/80 font-mono gap-2"
            >
              {scanStatus === 'running' ? <Square className="h-4 w-4" /> : <Play className="h-4 w-4" />}
              {scanStatus === 'running' ? 'SCANNING...' : 'RUN SCAN'}
            </Button>
          </div>

          {/* Terminal */}
          <TerminalLog isRunning={scanStatus === 'running'} target={target} onComplete={onScanComplete} />
        </div>

        {/* Config Panel */}
        <div className="bg-card rounded-lg border border-border neon-border p-4 space-y-4">
          <p className="text-xs text-muted-foreground uppercase tracking-wider">Configuration</p>
          {config.map(opt => (
            <div key={opt.label} className="flex items-center justify-between">
              <span className="text-sm">{opt.label}</span>
              {opt.type === 'toggle' ? (
                <Switch
                  checked={options[opt.label] ?? opt.default}
                  onCheckedChange={v => setOptions(prev => ({ ...prev, [opt.label]: v }))}
                />
              ) : (
                <Checkbox
                  checked={options[opt.label] ?? opt.default}
                  onCheckedChange={v => setOptions(prev => ({ ...prev, [opt.label]: !!v }))}
                />
              )}
            </div>
          ))}
          <div className="pt-2 border-t border-border">
            <p className="text-xs text-muted-foreground">
              Status: <span className={
                scanStatus === 'idle' ? 'text-muted-foreground' :
                scanStatus === 'running' ? 'text-warning' :
                'text-primary'
              }>{scanStatus.toUpperCase()}</span>
            </p>
          </div>
        </div>
      </div>

      {/* Results */}
      {results.length > 0 && (
        <div className="bg-card rounded-lg border border-border neon-border overflow-hidden">
          <div className="px-4 py-3 border-b border-border bg-muted/30 flex items-center justify-between">
            <span className="text-xs text-muted-foreground uppercase tracking-wider">
              Results — {results.length} finding(s)
            </span>
            <div className="flex gap-2">
              <Button size="sm" variant="outline" onClick={() => exportData('csv')} className="text-xs font-mono gap-1 border-border hover:bg-muted">
                <Download className="h-3 w-3" /> CSV
              </Button>
              <Button size="sm" variant="outline" onClick={() => exportData('json')} className="text-xs font-mono gap-1 border-border hover:bg-muted">
                <Download className="h-3 w-3" /> JSON
              </Button>
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border text-muted-foreground">
                  <th className="px-4 py-2 text-left">Asset</th>
                  <th className="px-4 py-2 text-left">Finding</th>
                  <th className="px-4 py-2 text-left">Severity</th>
                  <th className="px-4 py-2 text-left">Status</th>
                </tr>
              </thead>
              <tbody>
                {results.map(r => (
                  <tr key={r.id} className="border-b border-border/50 hover:bg-muted/20 transition-colors">
                    <td className="px-4 py-2 text-secondary">{r.asset}</td>
                    <td className="px-4 py-2">{r.finding}</td>
                    <td className="px-4 py-2"><SeverityBadge severity={r.severity} /></td>
                    <td className="px-4 py-2 text-muted-foreground uppercase">{r.status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
