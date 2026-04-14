const API_BASE_URL = import.meta.env.VITE_API_BASE_URL?.trim();

export const hasApiBaseUrl = Boolean(API_BASE_URL);

export class ApiError extends Error {
  constructor(message: string, public status?: number) {
    super(message);
    this.name = "ApiError";
  }
}

export async function apiRequest<T>(path: string, init?: RequestInit): Promise<T> {
  if (!API_BASE_URL) {
    throw new ApiError("API base URL is not configured");
  }

  const response = await fetch(`${API_BASE_URL}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
    ...init,
  });

  if (!response.ok) {
    throw new ApiError(`Request failed for ${path}`, response.status);
  }

  return response.json() as Promise<T>;
}
