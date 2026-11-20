import type { PageData, SessionInfo, SpaEnvelope } from "./types";

export class ApiError extends Error {
  status: number;
  errorField?: string;
  redirect?: string;
  unauthorized?: boolean;
  envelope?: SpaEnvelope;

  constructor(
    message: string,
    status: number,
    options?: {
      errorField?: string;
      redirect?: string;
      unauthorized?: boolean;
      envelope?: SpaEnvelope;
    },
  ) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.errorField = options?.errorField;
    this.redirect = options?.redirect;
    this.unauthorized = options?.unauthorized;
    this.envelope = options?.envelope;
  }
}

export interface SubmitResult {
  ok: boolean;
  status: number;
  redirect?: string;
  view?: string;
  notice?: string;
  data?: PageData;
  contentLocation?: string;
}

const ruleSetCatalogCache = new Map<string, Promise<string[]>>();

async function parseErrorResponse(response: Response): Promise<ApiError> {
  const contentType = response.headers.get("Content-Type") || "";
  const text = await response.text();
  if (contentType.includes("json")) {
    try {
      const parsed = JSON.parse(text) as SpaEnvelope & { error?: string };
      if (response.status === 401) {
        return new ApiError(parsed.error || "unauthorized", 401, {
          unauthorized: true,
          redirect: parsed.redirect || "/login",
        });
      }
      const message = parsed.error || parsed.data?.Error || `HTTP ${response.status}`;
      return new ApiError(message, response.status, {
        errorField: parsed.errorField || parsed.data?.ErrorField,
        envelope: parsed,
      });
    } catch {
      // fall through
    }
  }
  if (response.status === 401) {
    return new ApiError("unauthorized", 401, { unauthorized: true, redirect: "/login" });
  }
  return new ApiError(text.trim() || `HTTP ${response.status}`, response.status);
}

export async function fetchSession(): Promise<SessionInfo> {
  const response = await fetch("/api/session", {
    credentials: "same-origin",
    cache: "no-store",
    headers: { Accept: "application/json", "X-Theatropolis-SPA": "1" },
  });
  if (!response.ok) throw await parseErrorResponse(response);
  return (await response.json()) as SessionInfo;
}

export async function fetchMessages(locale?: string): Promise<{ locale: string; messages: Record<string, string> }> {
  const url = locale ? `/api/messages?locale=${encodeURIComponent(locale)}` : "/api/messages";
  const response = await fetch(url, {
    credentials: "same-origin",
    cache: "no-store",
    headers: { Accept: "application/json", "X-Theatropolis-SPA": "1" },
  });
  if (!response.ok) throw await parseErrorResponse(response);
  return (await response.json()) as { locale: string; messages: Record<string, string> };
}

export async function switchLanguage(locale: "en" | "zh-CN"): Promise<{ locale: string; messages: Record<string, string> }> {
  const response = await fetch(`/language/${encodeURIComponent(locale)}`, {
    credentials: "same-origin",
    cache: "no-store",
    headers: { Accept: "application/json", "X-Theatropolis-SPA": "1" },
  });
  if (!response.ok) throw await parseErrorResponse(response);
  return (await response.json()) as { locale: string; messages: Record<string, string> };
}

export async function fetchFreshCSRFToken(): Promise<string> {
  const response = await fetch("/session/csrf", {
    credentials: "same-origin",
    cache: "no-store",
    headers: { Accept: "application/json", "X-Theatropolis-SPA": "1" },
  });
  if (!response.ok) throw await parseErrorResponse(response);
  const data = (await response.json()) as { csrf_token?: string };
  if (!data.csrf_token) throw new ApiError("Session expired.", 401, { unauthorized: true, redirect: "/login" });
  return data.csrf_token;
}

export async function fetchPage(url: string, signal?: AbortSignal): Promise<SpaEnvelope> {
  const response = await fetch(url, {
    credentials: "same-origin",
    cache: "no-store",
    signal,
    headers: { Accept: "application/json", "X-Theatropolis-SPA": "1" },
  });
  if (!response.ok) throw await parseErrorResponse(response);
  const payload = (await response.json()) as SpaEnvelope;
  return payload;
}

export async function fetchJSON<T>(url: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  headers.set("Accept", "application/json");
  headers.set("X-Theatropolis-SPA", "1");
  const response = await fetch(url, {
    credentials: "same-origin",
    cache: "no-store",
    ...init,
    headers,
  });
  if (!response.ok) throw await parseErrorResponse(response);
  return (await response.json()) as T;
}

export function fetchRuleSetCatalog(kind: "geosite" | "geoip"): Promise<string[]> {
  const cached = ruleSetCatalogCache.get(kind);
  if (cached) return cached;
  const req = fetchJSON<{ options?: string[]; warning?: string }>(
    `/subscriptions/rule-set-options?kind=${encodeURIComponent(kind)}`,
  )
    .then((body) => {
      if (!Array.isArray(body?.options) || body.options.length === 0) {
        throw new Error(body?.warning || "rule-set-options returned no options");
      }
      return body.options;
    })
    .catch((err) => {
      ruleSetCatalogCache.delete(kind);
      throw err;
    });
  ruleSetCatalogCache.set(kind, req);
  return req;
}

export async function submitForm(
  action: string,
  fields: Record<string, string | string[] | undefined> | URLSearchParams,
  options?: { csrfToken?: string; formAdapter?: boolean },
): Promise<SubmitResult> {
  const params = fields instanceof URLSearchParams ? new URLSearchParams(fields) : new URLSearchParams();
  if (!(fields instanceof URLSearchParams)) {
    for (const [key, value] of Object.entries(fields)) {
      if (value === undefined) continue;
      if (Array.isArray(value)) {
        for (const item of value) params.append(key, item);
      } else {
        params.append(key, value);
      }
    }
  }
  if (options?.csrfToken && !params.has("csrf_token")) {
    params.set("csrf_token", options.csrfToken);
  }
  const headers: Record<string, string> = {
    Accept: "application/json",
    "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
    "X-Theatropolis-SPA": "1",
  };
  if (options?.formAdapter !== false) {
    headers["X-Theatropolis-Form"] = "1";
  }
  const response = await fetch(action, {
    method: "POST",
    credentials: "same-origin",
    cache: "no-store",
    headers,
    body: params,
  });
  if (response.status === 204) {
    return {
      ok: true,
      status: 204,
      redirect: response.headers.get("X-Theatropolis-Redirect") || undefined,
    };
  }
  if (!response.ok) {
    throw await parseErrorResponse(response);
  }
  const contentType = response.headers.get("Content-Type") || "";
  if (contentType.includes("json")) {
    const parsed = (await response.json()) as SpaEnvelope & { ok?: boolean; redirect?: string };
    return {
      ok: true,
      status: response.status,
      redirect: parsed.redirect,
      view: parsed.view,
      notice: parsed.notice || parsed.data?.Notice,
      data: parsed.data,
      contentLocation: response.headers.get("Content-Location") || undefined,
    };
  }
  return { ok: true, status: response.status };
}

export async function submitMultipart(action: string, formData: FormData): Promise<SubmitResult> {
  const response = await fetch(action, {
    method: "POST",
    credentials: "same-origin",
    cache: "no-store",
    headers: {
      Accept: "application/json",
      "X-Theatropolis-SPA": "1",
      "X-Theatropolis-Form": "1",
    },
    body: formData,
  });
  if (!response.ok) {
    throw await parseErrorResponse(response);
  }
  const parsed = (await response.json()) as SpaEnvelope & { ok?: boolean; redirect?: string };
  return {
    ok: true,
    status: response.status,
    redirect: parsed.redirect,
    view: parsed.view,
    notice: parsed.notice || parsed.data?.Notice,
    data: parsed.data,
    contentLocation: response.headers.get("Content-Location") || undefined,
  };
}

export async function downloadArchiveForm(
  action: string,
  fields: Record<string, string>,
): Promise<{ filename: string }> {
  const params = new URLSearchParams(fields);
  const response = await fetch(action, {
    method: "POST",
    credentials: "same-origin",
    cache: "no-store",
    headers: {
      Accept: "application/zip, application/json",
      "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
      "X-Theatropolis-SPA": "1",
      "X-Theatropolis-Form": "1",
    },
    body: params,
  });
  if (!response.ok) {
    throw await parseErrorResponse(response);
  }
  const contentType = response.headers.get("Content-Type") || "";
  if (!contentType.startsWith("application/zip")) {
    throw new ApiError(
      "The server did not return a migration archive. Your input has been kept; check the Master and try again.",
      response.status,
    );
  }
  const blob = await response.blob();
  const objectURL = URL.createObjectURL(blob);
  const disposition = response.headers.get("Content-Disposition") || "";
  const filename = disposition.match(/filename="?([^";]+)"?/)?.[1] || "theatropolis-migration.zip";
  const link = document.createElement("a");
  link.href = objectURL;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(objectURL), 60_000);
  return { filename };
}
