const API_URL = "http://localhost:3001";

export const BACKEND_UNAVAILABLE = "Unable to connect to server";

let onUnauthorized: (() => void) | null = null;

export function setUnauthorizedHandler(handler: (() => void) | null) {
  onUnauthorized = handler;
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const token = localStorage.getItem("token");
  const headers: Record<string, string> = {
    ...((options?.headers as Record<string, string>) || {}),
  };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  let res: Response;
  try {
    res = await fetch(`${API_URL}${path}`, { ...options, headers, cache: "no-store" });
  } catch {
    throw new ApiError(BACKEND_UNAVAILABLE, 0);
  }

  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: "Request failed" }));
    if (res.status === 401) {
      localStorage.removeItem("token");
      onUnauthorized?.();
    }
    throw new ApiError(body.error || "Request failed", res.status);
  }

  return res.json();
}

export class ApiError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

export interface AuthResponse {
  token: string;
  user: { id: string; email: string; role: string };
}

export interface UserInfo {
  id: string;
  email: string;
  role: string;
  status?: string;
}

export async function login(email: string, password: string): Promise<AuthResponse> {
  return request<AuthResponse>("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
}

export async function logout(): Promise<void> {
  await request("/api/auth/logout", { method: "POST" }).catch(() => {});
  localStorage.removeItem("token");
}

export async function getMe(): Promise<UserInfo> {
  return request<UserInfo>("/api/auth/me");
}

export async function getEvents() {
  return request<import("./types").SecurityEvent[]>("/api/events");
}

export async function getUsers(): Promise<UserInfo[]> {
  return request<UserInfo[]>("/api/users");
}

export async function createUser(user: { email: string; password: string; role: string }): Promise<UserInfo> {
  return request<UserInfo>("/api/users", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(user),
  });
}

export async function deleteUser(id: string): Promise<{ message: string }> {
  return request<{ message: string }>(`/api/users/${id}`, { method: "DELETE" });
}
