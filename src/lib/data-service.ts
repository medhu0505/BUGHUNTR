import {
  ACTIVITY_FEED,
  generateScanResults,
  getMockFindings,
  getModuleConfig,
  getStats,
  MODULES,
  type ActivityEntry,
  type DashboardStats,
  type Finding,
  type ModuleDefinition,
  type ModuleOption,
} from "@/lib/mock-data";
import { apiRequest, hasApiBaseUrl } from "@/lib/api-client";

export async function fetchModules(): Promise<ModuleDefinition[]> {
  if (!hasApiBaseUrl) return MODULES;
  try {
    return await apiRequest<ModuleDefinition[]>("/modules");
  } catch {
    return MODULES;
  }
}

export async function fetchFindings(): Promise<Finding[]> {
  if (!hasApiBaseUrl) return getMockFindings();
  try {
    return await apiRequest<Finding[]>("/findings");
  } catch {
    return getMockFindings();
  }
}

export async function fetchStats(): Promise<DashboardStats> {
  if (!hasApiBaseUrl) return getStats();
  try {
    return await apiRequest<DashboardStats>("/dashboard/stats");
  } catch {
    return getStats();
  }
}

export async function fetchActivityFeed(): Promise<ActivityEntry[]> {
  if (!hasApiBaseUrl) return ACTIVITY_FEED;
  try {
    return await apiRequest<ActivityEntry[]>("/dashboard/activity");
  } catch {
    return ACTIVITY_FEED;
  }
}

export async function fetchModuleConfig(moduleId: string): Promise<ModuleOption[]> {
  if (!hasApiBaseUrl) return getModuleConfig(moduleId);
  try {
    return await apiRequest<ModuleOption[]>(`/modules/${encodeURIComponent(moduleId)}/config`);
  } catch {
    return getModuleConfig(moduleId);
  }
}

export async function runScan(moduleId: string, target: string): Promise<Finding[]> {
  if (!hasApiBaseUrl) return generateScanResults(moduleId, target);
  try {
    return await apiRequest<Finding[]>("/scans/run", {
      method: "POST",
      body: JSON.stringify({ moduleId, target }),
    });
  } catch {
    return generateScanResults(moduleId, target);
  }
}
