import {
  type ActivityEntry,
  type DashboardStats,
  type Finding,
  type ModuleDefinition,
  type ModuleOption,
} from "@/lib/mock-data";
import { ApiError, apiRequest, getSseBaseUrl, hasApiBaseUrl } from "@/lib/api-client";

export interface ScanEvent {
  type: "log" | "finding" | "complete" | "ping";
  message?: string;
  data?: Finding;
  timestamp?: string;
}

export interface ScanDetail {
  scanId: string;
  module: string;
  target: string;
  status: "running" | "complete" | "failed";
  startTime: string;
  endTime?: string;
  totalFindings?: number;
  criticalCount?: number;
  highCount?: number;
  findings?: Finding[];
}

export interface TakeoverCnameRecord {
  sub: string;
  cname: string;
  provider: string;
  fp?: { provider: string; takeover: boolean; status_match?: string | null };
}

export interface TakeoverVulnRecord {
  sub: string;
  cname: string;
  provider: string;
  nxdomain: boolean;
  http_code: number;
  body_match: boolean;
  match_string?: string | null;
  confidence: "low" | "medium" | "high";
  severity: "low" | "medium" | "high" | "critical";
  verified?: boolean;
  verify_nxdomain_1?: boolean;
  verify_nxdomain_2?: boolean;
  verify_http?: number;
}

export async function fetchModules(): Promise<ModuleDefinition[]> {
  return apiRequest<ModuleDefinition[]>("/modules");
}

export async function fetchFindings(): Promise<Finding[]> {
  return apiRequest<Finding[]>("/findings");
}

export async function fetchRecentFindings(limit = 20): Promise<Finding[]> {
  const findings = await apiRequest<Finding[]>("/findings/recent");
  return findings.slice(0, limit);
}

export async function fetchStats(): Promise<DashboardStats> {
  return apiRequest<DashboardStats>("/dashboard/stats");
}

export async function fetchActivityFeed(): Promise<ActivityEntry[]> {
  const feed = await apiRequest<Array<{ time: string; type: ActivityEntry["type"]; message: string }>>("/dashboard/activity");
  return feed.map((entry) => ({
    time: entry.time,
    type: entry.type,
    msg: entry.message,
  }));
}

export async function fetchModuleConfig(moduleId: string): Promise<ModuleOption[]> {
  return apiRequest<ModuleOption[]>(`/modules/${encodeURIComponent(moduleId)}/config`);
}

export async function runScan(moduleId: string, target: string): Promise<Finding[]> {
  const response = await apiRequest<Finding[] | { scan_id?: string; status?: string }>("/scans/run", {
    method: "POST",
    body: JSON.stringify({ moduleId, target }),
  }, 180000);

  // If response is already an array of findings, return directly
  if (Array.isArray(response)) {
    return response;
  }

  const scanId = response.scan_id;
  if (!scanId) {
    return [];
  }

  // Stream results via SSE with polling fallback
  const findings: Finding[] = [];
  const scanComplete = new Promise<Finding[]>((resolve) => {
    const unsubscribe = subscribeToScan(scanId, (event) => {
      if (event.type === "finding" && event.data) {
        findings.push(event.data);
      } else if (event.type === "complete") {
        unsubscribe();
        resolve(findings);
      }
    });

    // Polling fallback: if SSE doesn't complete in 5 minutes, fetch results directly
    const timeout = setTimeout(() => {
      unsubscribe();
      fetchScanResults(scanId).then(resolve).catch(() => resolve(findings));
    }, 300000);

    // Clear timeout if SSE completes
    const originalResolve = resolve;
    resolve = ((value) => {
      clearTimeout(timeout);
      originalResolve(value);
    }) as typeof resolve;
  });

  return scanComplete;
}

export async function startScan(moduleId: string, target: string, options: Record<string, boolean | number>): Promise<string> {
  if (!hasApiBaseUrl) {
    throw new ApiError("API base URL is not configured");
  }
  const response = await apiRequest<{ scan_id: string }>("/scans/run", {
    method: "POST",
    body: JSON.stringify({ moduleId, target, options }),
  });
  return response.scan_id;
}

export function subscribeToScan(scanId: string, onEvent: (event: ScanEvent) => void): () => void {
  const source = new EventSource(`${getSseBaseUrl()}/stream/${encodeURIComponent(scanId)}`);
  source.onmessage = (message) => {
    try {
      const parsed = JSON.parse(message.data) as ScanEvent;
      onEvent(parsed);
    } catch {
      // Ignore malformed event chunks.
    }
  };
  source.onerror = () => {
    source.close();
  };
  return () => source.close();
}

export async function fetchScanResults(scanId: string): Promise<Finding[]> {
  try {
    return await apiRequest<Finding[]>(`/results/${encodeURIComponent(scanId)}`);
  } catch {
    const detail = await apiRequest<{ findings?: Finding[] }>(`/scans/${encodeURIComponent(scanId)}`);
    return detail.findings ?? [];
  }
}

export async function fetchScanDetail(scanId: string): Promise<ScanDetail> {
  return apiRequest<ScanDetail>(`/scans/${encodeURIComponent(scanId)}`);
}

export async function clearScanHistory(): Promise<{ status: string; removedScans: number; removedFindings: number }> {
  return apiRequest<{ status: string; removedScans: number; removedFindings: number }>(
    "/scans/clear",
    { method: "POST" },
  );
}

export async function takeoverEnumerate(target: string): Promise<{ target: string; subdomains: string[]; logs: string[] }> {
  return apiRequest<{ target: string; subdomains: string[]; logs: string[] }>(`/takeover/enumerate?target=${encodeURIComponent(target)}`, undefined, 180000);
}

export async function takeoverTriage(subdomains: string[]): Promise<{ cname: TakeoverCnameRecord[]; a: Array<{ sub: string; ips: string[] }>; dead: Array<{ sub: string }> }> {
  return apiRequest<{ cname: TakeoverCnameRecord[]; a: Array<{ sub: string; ips: string[] }>; dead: Array<{ sub: string }> }>(
    "/takeover/triage",
    { method: "POST", body: JSON.stringify({ subdomains }) },
    180000,
  );
}

export async function takeoverScan(cnameRecords: TakeoverCnameRecord[]): Promise<{ vulnerable: TakeoverVulnRecord[]; logs: string[] }> {
  return apiRequest<{ vulnerable: TakeoverVulnRecord[]; logs: string[] }>(
    "/takeover/scan",
    { method: "POST", body: JSON.stringify({ cname_records: cnameRecords }) },
    180000,
  );
}

export async function takeoverVerify(vulnerable: TakeoverVulnRecord[]): Promise<{ verified: TakeoverVulnRecord[]; logs: string[] }> {
  return apiRequest<{ verified: TakeoverVulnRecord[]; logs: string[] }>(
    "/takeover/verify",
    { method: "POST", body: JSON.stringify({ vulnerable }) },
    180000,
  );
}

export async function importBurpJson(file: File): Promise<{ message: string }> {
  const formData = new FormData();
  formData.append('file', file);
  
  return apiRequest<{ message: string }>("/import/burp", {
    method: "POST",
    body: formData,
    headers: {}, // Let browser set Content-Type for FormData
  });
}
