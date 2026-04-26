const RAW_API_BASE_URL = import.meta.env.VITE_API_BASE_URL?.trim();

function normalizeApiBaseUrl(baseUrl?: string): string | undefined {
  if (!baseUrl) return "/api";
  const trimmed = baseUrl.replace(/\/+$/, "");
  return trimmed.endsWith("/api") ? trimmed : `${trimmed}/api`;
}

export const apiBaseUrl = normalizeApiBaseUrl(RAW_API_BASE_URL);
export const hasApiBaseUrl = Boolean(apiBaseUrl);

export class ApiError extends Error {
  constructor(message: string, public status?: number) {
    super(message);
    this.name = "ApiError";
  }
}

function buildApiCandidates(): string[] {
  const candidates = new Set<string>();
  if (apiBaseUrl) {
    candidates.add(apiBaseUrl);
  }
  if (typeof window !== "undefined") {
    const protocol = window.location.protocol;
    const hostname = window.location.hostname || "localhost";
    candidates.add(`${protocol}//${hostname}:5000/api`);
    candidates.add("http://127.0.0.1:5000/api");
    candidates.add("http://localhost:5000/api");
  }
  return Array.from(candidates);
}

function withTimeout(init: RequestInit | undefined, timeoutMs = 8000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const requestInit: RequestInit = { ...(init ?? {}), signal: controller.signal };
  return { requestInit, timer };
}

export function getSseBaseUrl(): string {
  const [primary] = buildApiCandidates();
  return primary || "/api";
}

export async function apiRequest<T>(path: string, init?: RequestInit, timeoutMs = 8000): Promise<T> {
  const candidates = buildApiCandidates();
  let lastError: unknown = new ApiError("API base URL is not configured");

  for (const base of candidates) {
    const { requestInit, timer } = withTimeout(
      {
        headers: {
          "Content-Type": "application/json",
          ...(init?.headers ?? {}),
        },
        ...init,
      },
      timeoutMs,
    );

    try {
      const response = await fetch(`${base}${path}`, requestInit);
      if (!response.ok) {
        let errorMessage = `Request failed for ${path}`;
        try {
          const errorBody = (await response.json()) as { error?: string; message?: string };
          errorMessage = errorBody.error || errorBody.message || errorMessage;
        } catch {
          // Non-JSON error response; keep fallback message.
        }
        lastError = new ApiError(errorMessage, response.status);
        // For most client errors, don't hop across candidates; backend responded.
        if (response.status >= 400 && response.status < 500 && response.status !== 404) {
          break;
        }
        continue;
      }
      return response.json() as Promise<T>;
    } catch (error) {
      lastError = error;
    } finally {
      clearTimeout(timer);
    }
  }

  if (lastError instanceof ApiError) {
    throw lastError;
  }
  throw new ApiError(`Unable to reach backend for ${path}`);
}
