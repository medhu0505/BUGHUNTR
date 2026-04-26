import { useState, useCallback, useEffect, useRef } from "react";
import { useParams } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Play, Download, Square, ChevronDown, ChevronRight, Trash2, Eraser } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Checkbox } from "@/components/ui/checkbox";
import { TerminalLog } from "@/components/TerminalLog";
import { SeverityBadge } from "@/components/SeverityBadge";
import { fetchModuleConfig, fetchModules, fetchScanDetail, fetchScanResults, startScan, subscribeToScan, takeoverEnumerate, takeoverScan, takeoverTriage, takeoverVerify, type TakeoverCnameRecord, type TakeoverVulnRecord } from "@/lib/data-service";
import { type Finding, type ModuleOption, type ScanStatus } from "@/lib/mock-data";

async function fetchResultsWithRetry(scanId: string, maxAttempts = 4): Promise<Finding[]> {
  let lastError: unknown;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await fetchScanResults(scanId);
    } catch (error) {
      lastError = error;
      await new Promise((resolve) => setTimeout(resolve, 600 * attempt));
    }
  }
  throw lastError;
}

const ACTIVE_SCAN_KEY = "bbh-active-scan";

function saveActiveScan(moduleId: string, target: string, scanId: string) {
  localStorage.setItem(ACTIVE_SCAN_KEY, JSON.stringify({ moduleId, target, scanId }));
}

function readActiveScan(): { moduleId: string; target: string; scanId: string } | null {
  const raw = localStorage.getItem(ACTIVE_SCAN_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as { moduleId: string; target: string; scanId: string };
  } catch {
    return null;
  }
}

function clearActiveScan() {
  localStorage.removeItem(ACTIVE_SCAN_KEY);
}

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
  const [options, setOptions] = useState<Record<string, boolean | number>>({});
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);
  const [scanLogs, setScanLogs] = useState<string[]>([]);
  const unsubscribeRef = useRef<(() => void) | null>(null);
  const [takeoverSubdomains, setTakeoverSubdomains] = useState<string[]>([]);
  const [takeoverCnames, setTakeoverCnames] = useState<TakeoverCnameRecord[]>([]);
  const [takeoverVulns, setTakeoverVulns] = useState<TakeoverVulnRecord[]>([]);
  const preserveSubscriptionRef = useRef(false); // Preserve subscription when navigating away during active scan

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

  // Warn user if they try to leave with an active scan
  useEffect(() => {
    const handleBeforeUnload = (e: BeforeUnloadEvent) => {
      if (scanStatus === "running") {
        const msg = "A scan is in progress. It will continue running in the background. Are you sure?";
        e.preventDefault();
        e.returnValue = msg;
        return msg;
      }
    };

    window.addEventListener("beforeunload", handleBeforeUnload);
    return () => window.removeEventListener("beforeunload", handleBeforeUnload);
  }, [scanStatus]);

  const runScan = useCallback(() => {
    if (!target.trim()) {
      toast.error('Please enter a target');
      return;
    }
    setScanStatus('running');
    setResults([]);
    setExpandedFinding(null);
    setScanLogs([]);
    toast('Scan started', { description: `Scanning ${target}...` });
    unsubscribeRef.current?.();
    unsubscribeRef.current = null;
    if (moduleId === "subdomain-takeover") {
      (async () => {
        try {
          setScanLogs((prev) => [...prev, `${new Date().toLocaleTimeString()} [*] Stage 1: Enumerating subdomains...`]);
          const enumResponse = await takeoverEnumerate(target);
          setTakeoverSubdomains(enumResponse.subdomains);
          setScanLogs((prev) => [...prev, ...enumResponse.logs.map((line) => `${new Date().toLocaleTimeString()} ${line}`)]);

          if (enumResponse.subdomains.length === 0) {
            setScanLogs((prev) => [...prev, `${new Date().toLocaleTimeString()} [WARN] No subdomains found. Takeover scan cannot continue.`]);
            setScanStatus("complete");
            clearActiveScan();
            toast.warning("No subdomains enumerated. Takeover scan aborted.");
            return;
          }

          setScanLogs((prev) => [...prev, `${new Date().toLocaleTimeString()} [*] Stage 2: Performing DNS triage...`]);
          const triage = await takeoverTriage(enumResponse.subdomains);
          setTakeoverCnames(triage.cname);
          setScanLogs((prev) => [
            ...prev,
            `${new Date().toLocaleTimeString()} CNAME triage complete: ${triage.cname.length} CNAME, ${triage.a.length} A records, ${triage.dead.length} dead`,
          ]);

          if (triage.cname.length === 0) {
            setScanLogs((prev) => [...prev, `${new Date().toLocaleTimeString()} [WARN] No CNAME records found. Takeover scan aborted.`]);
            setScanStatus("complete");
            clearActiveScan();
            toast.info("No CNAME records found. Takeover scan completed.");
            return;
          }

          setScanLogs((prev) => [...prev, `${new Date().toLocaleTimeString()} [*] Stage 3: Scanning CNAME records...`]);
          const scan = await takeoverScan(triage.cname);
          setTakeoverVulns(scan.vulnerable);
          setScanLogs((prev) => [...prev, ...scan.logs.map((line) => `${new Date().toLocaleTimeString()} ${line}`)]);

          setScanLogs((prev) => [...prev, `${new Date().toLocaleTimeString()} [*] Stage 4: Verifying findings...`]);
          const verified = await takeoverVerify(scan.vulnerable);
          setScanLogs((prev) => [...prev, ...verified.logs.map((line) => `${new Date().toLocaleTimeString()} ${line}`)]);

          const findings = verified.verified.map((item, idx) => ({
            id: `takeover-${idx}-${item.sub}`,
            asset: item.sub,
            finding: item.verified
              ? `Confirmed takeover candidate via ${item.provider} (${item.confidence})`
              : `Unconfirmed takeover candidate via ${item.provider} (${item.confidence})`,
            severity: item.severity,
            status: (item.verified ? "confirmed" : "false-positive") as const,
            module: "subdomain-takeover",
            timestamp: new Date().toISOString(),
            details: `CNAME=${item.cname}; NXDOMAIN=${item.verify_nxdomain_1 || item.verify_nxdomain_2}; HTTP=${item.verify_http}`,
            vulnerableObjects: [{ type: "cname", url: item.cname, description: item.verified ? "Verified dangling/provider-match candidate" : "Candidate did not pass verification" }],
          })) as Finding[];

          setResults(findings);
          setScanStatus("complete");
          clearActiveScan();
          queryClient.invalidateQueries({ queryKey: ["findings"] });
          queryClient.invalidateQueries({ queryKey: ["stats"] });
          queryClient.invalidateQueries({ queryKey: ["activity-feed"] });
          const confirmed = findings.filter((f) => f.status === "confirmed").length;
          if (confirmed > 0) {
            toast.success(`Takeover scan complete: ${confirmed} confirmed finding(s)`);
          } else {
            toast.info("Takeover scan complete: no confirmed findings");
          }
        } catch (error) {
          const errorMsg = error instanceof Error ? error.message : "Subdomain takeover workflow failed";
          setScanLogs((prev) => [...prev, `${new Date().toLocaleTimeString()} [ERROR] ${errorMsg}`]);
          setScanStatus("idle");
          toast.error(`Takeover scan failed: ${errorMsg}`);
        }
      })();
      return;
    }
    startScan(moduleId || "", target, options)
      .then((scanId) => {
        saveActiveScan(moduleId || "", target, scanId);
        preserveSubscriptionRef.current = true; // Preserve subscription when user navigates away
        const unsubscribe = subscribeToScan(scanId, (event) => {
          if (event.type === "ping") return;
          if (event.type === "log" && event.message) {
            const time = event.timestamp ? new Date(event.timestamp).toLocaleTimeString() : new Date().toLocaleTimeString();
            setScanLogs((prev) => [...prev, `${time} ${event.message}`]);
            return;
          }
          if (event.type === "finding" && event.data) {
            setScanLogs((prev) => [...prev, `${new Date().toLocaleTimeString()} [!] ${event.data.finding}`]);
            return;
          }
          if (event.type === "complete") {
            unsubscribe();
            unsubscribeRef.current = null;
            preserveSubscriptionRef.current = false; // Scan completed, can close connection on unmount
            fetchResultsWithRetry(scanId)
              .then((findings) => {
                setResults(findings);
                setScanStatus("complete");
                clearActiveScan();
                queryClient.invalidateQueries({ queryKey: ["findings"] });
                queryClient.invalidateQueries({ queryKey: ["stats"] });
                queryClient.invalidateQueries({ queryKey: ["activity-feed"] });
                const criticals = findings.filter((f) => f.severity === "critical").length;
                if (criticals > 0) {
                  toast.error(`${criticals} critical finding(s) detected!`);
                } else {
                  toast.success("Scan complete");
                }
              })
              .catch(() => {
                setScanStatus("complete");
                toast.error("Scan finished, but result sync failed. Please refresh findings.");
              });
          }
        });
        unsubscribeRef.current = unsubscribe;
      })
      .catch(() => {
        setScanStatus("idle");
        preserveSubscriptionRef.current = false;
        toast.error("Scan failed. Please try again.");
      });
  }, [moduleId, options, queryClient, target]);

  const stopScan = useCallback(() => {
    if (scanStatus !== "running") {
      return;
    }
    unsubscribeRef.current?.();
    unsubscribeRef.current = null;
    preserveSubscriptionRef.current = false;
    setScanStatus("idle");
    setScanLogs((prev) => [...prev, `${new Date().toLocaleTimeString()} [WARN] Scan view stopped by user`]);
    toast("Stopped viewing scan stream");
  }, [scanStatus]);

  const clearLogs = useCallback(() => {
    setScanLogs([]);
    toast.success("Logs cleared");
  }, []);

  const clearResults = useCallback(() => {
    setResults([]);
    setExpandedFinding(null);
    toast.success("Results cleared");
  }, []);

  const runTakeoverEnumerate = useCallback(async () => {
    if (!target.trim()) {
      toast.error("Please enter a target");
      return;
    }
    try {
      setScanLogs((prev) => [...prev, `${new Date().toLocaleTimeString()} [*] Starting enumeration...`]);
      const response = await takeoverEnumerate(target);
      setTakeoverSubdomains(response.subdomains);
      setTakeoverCnames([]);
      setTakeoverVulns([]);
      setScanLogs((prev) => [...prev, ...response.logs.map((line) => `${new Date().toLocaleTimeString()} ${line}`)]);
      toast.success(`Enumeration complete: ${response.subdomains.length} subdomains`);
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : "Enumeration failed";
      setScanLogs((prev) => [...prev, `${new Date().toLocaleTimeString()} [ERROR] ${errorMsg}`]);
      toast.error(`Enumeration failed: ${errorMsg}`);
    }
  }, [target]);

  const runTakeoverTriage = useCallback(async () => {
    if (takeoverSubdomains.length === 0) {
      toast.error("Run enumeration first");
      return;
    }
    try {
      setScanLogs((prev) => [...prev, `${new Date().toLocaleTimeString()} [*] Starting DNS triage...`]);
      const triage = await takeoverTriage(takeoverSubdomains);
      setTakeoverCnames(triage.cname);
      setTakeoverVulns([]);
      setScanLogs((prev) => [
        ...prev,
        `${new Date().toLocaleTimeString()} CNAME triage complete: ${triage.cname.length} CNAME, ${triage.a.length} A records, ${triage.dead.length} dead`,
      ]);
      toast.success("DNS triage complete");
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : "Triage failed";
      setScanLogs((prev) => [...prev, `${new Date().toLocaleTimeString()} [ERROR] ${errorMsg}`]);
      toast.error(`Triage failed: ${errorMsg}`);
    }
  }, [takeoverSubdomains]);

  const runTakeoverScan = useCallback(async () => {
    if (takeoverCnames.length === 0) {
      toast.error("Run DNS triage first");
      return;
    }
    try {
      setScanLogs((prev) => [...prev, `${new Date().toLocaleTimeString()} [*] Scanning ${takeoverCnames.length} CNAME records...`]);
      const scan = await takeoverScan(takeoverCnames);
      setTakeoverVulns(scan.vulnerable);
      setScanLogs((prev) => [...prev, ...scan.logs.map((line) => `${new Date().toLocaleTimeString()} ${line}`)]);
      toast.success(`CNAME scan complete: ${scan.vulnerable.length} candidate(s)`);
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : "CNAME scan failed";
      setScanLogs((prev) => [...prev, `${new Date().toLocaleTimeString()} [ERROR] ${errorMsg}`]);
      toast.error(`CNAME scan failed: ${errorMsg}`);
    }
  }, [takeoverCnames]);

  const runTakeoverVerify = useCallback(async () => {
    if (takeoverVulns.length === 0) {
      toast.error("Run CNAME scan first");
      return;
    }
    try {
      setScanLogs((prev) => [...prev, `${new Date().toLocaleTimeString()} [*] Verifying ${takeoverVulns.length} candidates...`]);
      const verified = await takeoverVerify(takeoverVulns);
      const findings = verified.verified
        .filter((item) => item.verified)
        .map((item, idx) => ({
          id: `takeover-${idx}-${item.sub}`,
          asset: item.sub,
          finding: `Confirmed takeover candidate via ${item.provider} (${item.confidence})`,
          severity: item.severity,
          status: "confirmed" as const,
          module: "subdomain-takeover",
          timestamp: new Date().toISOString(),
          details: `CNAME=${item.cname}; NXDOMAIN=${item.verify_nxdomain_1 || item.verify_nxdomain_2}; HTTP=${item.verify_http}`,
          vulnerableObjects: [{ type: "cname", url: item.cname, description: "Verified dangling/provider-match candidate" }],
        })) as Finding[];
      setResults(findings);
      setScanLogs((prev) => [...prev, ...verified.logs.map((line) => `${new Date().toLocaleTimeString()} ${line}`)]);
      toast.success(`Verification complete: ${findings.length} confirmed`);
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : "Verification failed";
      setScanLogs((prev) => [...prev, `${new Date().toLocaleTimeString()} [ERROR] ${errorMsg}`]);
      toast.error(`Verification failed: ${errorMsg}`);
    }
  }, [takeoverVulns]);

  useEffect(() => {
    const active = readActiveScan();
    if (!active || !moduleId || active.moduleId !== moduleId) {
      return;
    }

    setTarget(active.target);
    setScanStatus("running");
    setScanLogs((prev) => [...prev, `${new Date().toLocaleTimeString()} Resumed background scan for ${active.target}`]);
    unsubscribeRef.current?.();
    preserveSubscriptionRef.current = true; // Mark that we should preserve this subscription

    const unsubscribe = subscribeToScan(active.scanId, (event) => {
      if (event.type === "ping") return;
      if (event.type === "log" && event.message) {
        const time = event.timestamp ? new Date(event.timestamp).toLocaleTimeString() : new Date().toLocaleTimeString();
        setScanLogs((prev) => [...prev, `${time} ${event.message}`]);
        return;
      }
      if (event.type === "complete") {
        unsubscribe();
        unsubscribeRef.current = null;
        preserveSubscriptionRef.current = false;
        fetchScanDetail(active.scanId)
          .then((detail) => {
            setResults(detail.findings ?? []);
            setScanStatus("complete");
            clearActiveScan();
            toast.success("Background scan completed!");
          })
          .catch(() => {
            setScanStatus("idle");
          });
      }
    });
    unsubscribeRef.current = unsubscribe;

    return () => {
      // Only close connection if scan is complete or explicitly stopped
      // If scan is still running, preserve the connection to avoid abortion
      if (!preserveSubscriptionRef.current) {
        unsubscribeRef.current?.();
        unsubscribeRef.current = null;
      }
    };
  }, [moduleId]);

  const exportData = (format: 'csv' | 'json') => {
    if (format === 'json') {
      const blob = new Blob([JSON.stringify(results, null, 2)], { type: 'application/json' });
      downloadBlob(blob, `${moduleId}-results.json`);
    } else {
      const csv = [
        'Asset,Finding,Severity,Status,VulnerableObjects',
        ...results.map(r => {
          const vulnObjs = r.vulnerableObjects?.map(v => v.url).join('; ') || '';
          return `"${r.asset}","${r.finding}","${r.severity}","${r.status}","${vulnObjs}"`;
        })
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

      {moduleId === "subdomain-takeover" && (
        <div className="bg-card rounded-lg border border-border neon-border p-4 space-y-3">
          <p className="text-xs text-muted-foreground uppercase tracking-wider">Guided Takeover Workflow</p>
          <div className="flex flex-wrap gap-2">
            <Button size="sm" variant="outline" onClick={runTakeoverEnumerate} disabled={!target.trim()}>
              Stage 1: Enumerate
            </Button>
            <Button size="sm" variant="outline" onClick={runTakeoverTriage} disabled={takeoverSubdomains.length === 0}>
              Stage 2: DNS Triage
            </Button>
            <Button size="sm" variant="outline" onClick={runTakeoverScan} disabled={takeoverCnames.length === 0}>
              Stage 3: Scan CNAMEs
            </Button>
            <Button size="sm" variant="outline" onClick={runTakeoverVerify} disabled={takeoverVulns.length === 0}>
              Stage 4: Verify Findings
            </Button>
          </div>
          <p className="text-xs text-muted-foreground">
            Subdomains: {takeoverSubdomains.length} | CNAMEs: {takeoverCnames.length} | Candidates: {takeoverVulns.length}
          </p>
        </div>
      )}

      {/* Target + Config */}
      <div className="grid lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 space-y-4">
          <div className="flex gap-2">
            <Input
              placeholder="Enter target domain or URL..."
              value={target}
              onChange={e => setTarget(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && scanStatus !== "running") {
                  runScan();
                }
              }}
              className="bg-input border-border font-mono text-sm placeholder:text-muted-foreground"
            />
            <Button
              onClick={scanStatus === "running" ? stopScan : runScan}
              disabled={scanStatus === "running" ? false : !target.trim()}
              className="bg-primary text-primary-foreground hover:bg-primary/80 font-mono gap-2"
            >
              {scanStatus === 'running' ? <Square className="h-4 w-4" /> : <Play className="h-4 w-4" />}
              {scanStatus === 'running' ? 'STOP' : 'RUN SCAN'}
            </Button>
            <Button
              variant="outline"
              onClick={clearLogs}
              className="font-mono gap-2"
            >
              <Eraser className="h-4 w-4" />
              CLEAR LOGS
            </Button>
          </div>

          {/* Terminal */}
          <TerminalLog isRunning={scanStatus === 'running'} lines={scanLogs} />
        </div>

        {/* Config Panel */}
        <div className="bg-card rounded-lg border border-border neon-border p-4 space-y-4">
          <p className="text-xs text-muted-foreground uppercase tracking-wider">Configuration</p>
          {config.map(opt => (
            <div key={opt.label} className="flex items-center justify-between">
              <span className="text-sm">{opt.label}</span>
              {opt.type === 'toggle' ? (
                <Switch
                  checked={Boolean(options[opt.label] ?? opt.default)}
                  onCheckedChange={v => setOptions(prev => ({ ...prev, [opt.label]: v }))}
                />
              ) : opt.type === "checkbox" ? (
                <Checkbox
                  checked={Boolean(options[opt.label] ?? opt.default)}
                  onCheckedChange={v => setOptions(prev => ({ ...prev, [opt.label]: !!v }))}
                />
              ) : (
                <Input
                  type="number"
                  min={1}
                  value={String(options[opt.label] ?? opt.default)}
                  onChange={(e) => {
                    const next = Number(e.target.value);
                    setOptions((prev) => ({ ...prev, [opt.label]: Number.isFinite(next) && next > 0 ? next : 1 }));
                  }}
                  className="w-20 h-8 text-xs"
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
              <Button size="sm" variant="outline" onClick={clearResults} className="text-xs font-mono gap-1 border-border hover:bg-muted">
                <Trash2 className="h-3 w-3" /> CLEAR
              </Button>
              <Button size="sm" variant="outline" onClick={() => exportData('csv')} className="text-xs font-mono gap-1 border-border hover:bg-muted">
                <Download className="h-3 w-3" /> CSV
              </Button>
              <Button size="sm" variant="outline" onClick={() => exportData('json')} className="text-xs font-mono gap-1 border-border hover:bg-muted">
                <Download className="h-3 w-3" /> JSON
              </Button>
            </div>
          </div>
          <div className="space-y-0 divide-y divide-border">
            {results.map(r => (
              <div key={r.id} className="hover:bg-muted/20 transition-colors">
                <button
                  type="button"
                  className="w-full px-4 py-3 flex items-center gap-3 text-left"
                  onClick={() => setExpandedFinding(expandedFinding === r.id ? null : r.id)}
                  aria-expanded={expandedFinding === r.id}
                >
                  {r.vulnerableObjects && r.vulnerableObjects.length > 0 ? (
                    expandedFinding === r.id ? 
                      <ChevronDown className="h-4 w-4 text-primary shrink-0" /> :
                      <ChevronRight className="h-4 w-4 text-muted-foreground shrink-0" />
                  ) : (
                    <div className="h-4 w-4" />
                  )}
                  <SeverityBadge severity={r.severity} />
                  <div className="flex-1 min-w-0">
                    <p className="font-semibold text-sm">{r.finding}</p>
                    <p className="text-xs text-muted-foreground">{r.asset}</p>
                  </div>
                  <span className="text-xs text-muted-foreground uppercase shrink-0">{r.status}</span>
                </button>
                {expandedFinding === r.id && (
                  <div className="px-4 pb-4 pl-12 space-y-3 border-t border-border/30 terminal-bg">
                    <div className="pt-3">
                      <p className="text-xs text-muted-foreground uppercase tracking-wider mb-2">Details</p>
                      <p className="text-sm text-foreground">{r.details}</p>
                    </div>
                    {r.vulnerableObjects && r.vulnerableObjects.length > 0 && (
                      <div>
                        <p className="text-xs text-muted-foreground uppercase tracking-wider mb-2">Vulnerable Objects</p>
                        <div className="space-y-2">
                          {r.vulnerableObjects.map((obj, idx) => (
                            <div key={idx} className="bg-muted/50 rounded px-3 py-2 space-y-1">
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
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
