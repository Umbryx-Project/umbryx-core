export const BASE = '/api';

export interface ApiError extends Error {
  status: number;
  code?: string;
  details?: unknown;
  serverNote?: string;
}

function makeApiError(msg: string, status: number, code?: string, details?: unknown, serverNote?: string): ApiError {
  const err = new Error(msg) as ApiError;
  err.status = status;
  if (code !== undefined) err.code = code;
  if (details !== undefined) err.details = details;
  if (serverNote !== undefined) err.serverNote = serverNote;
  return err;
}

export async function req(
  method: string,
  path: string,
  body?: unknown,
  authRequired = true,
): Promise<unknown> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 30_000);
  const opts: RequestInit = { method, headers, credentials: 'include', signal: controller.signal, cache: 'no-store' };
  if (body !== undefined) opts.body = JSON.stringify(body);
  let res: Response;
  try {
    res = await fetch(BASE + path, opts);
  } catch (err) {
    throw makeApiError(err instanceof DOMException && err.name === 'AbortError' ? 'Request timed out' : String(err), 0);
  } finally {
    clearTimeout(timer);
  }
  if (res.status === 204) return null;
  if (res.status === 401 && authRequired) {
    globalThis.dispatchEvent(new Event('rt:logout'));
    throw makeApiError('Unauthorized', 401);
  }
  if (res.status === 409) {
    const data = await res.json().catch(() => ({})) as Record<string, unknown>;
    const msg = (data.message as string) || (data.detail as string) || 'conflict';
    throw makeApiError(msg, 409, (data.code as string) || 'conflict', data.details, msg);
  }
  if (!res.ok) {
    const text = await res.text();
    let msg = text;
    let code: string | undefined;
    let details: unknown;
    let parsed: Record<string, unknown> | undefined;
    try {
      parsed = JSON.parse(text) as Record<string, unknown>;
      // `error` is slowapi's rate-limit payload key — without it the raw
      // JSON blob ended up in login error banners verbatim (found live)
      msg =
        (parsed.message as string) ||
        (parsed.detail as string) ||
        (parsed.error as string) ||
        text;
      code = parsed.code as string | undefined;
      details = parsed.details;
    } catch {}
    // ROE/scope gate rejection — surface an actionable alert (cancel job /
    // request scope extension) instead of a bare error toast.
    if (res.status === 403 && code === 'roe_violation') {
      globalThis.dispatchEvent(new CustomEvent('roe:alert', {
        detail: {
          kind: 'blocked',
          message: msg,
          outOfScope: (parsed?.out_of_scope as string[]) || [],
          jobStatus: 'failed',
        },
      }));
    }
    throw makeApiError(msg, res.status, code, details);
  }
  const json = await res.json().catch(() => null);
  // 202 from the ROE requires_approval gate: the job exists but is held —
  // never let the UI read this as "running". The global alert offers
  // approve/reject/cancel.
  if (json && typeof json === 'object' && (json as Record<string, unknown>).code === 'roe_approval_required') {
    const data = json as Record<string, unknown>;
    globalThis.dispatchEvent(new CustomEvent('roe:alert', {
      detail: {
        kind: 'awaiting',
        message: (data.detail as string) || 'Job held for ROE approval',
        activities: (data.activities as string[]) || [],
        jobStatus: (data.job_status as string) || 'awaiting_approval',
      },
    }));
  }
  return json;
}

export async function upload(path: string, file: File, fieldName = 'file'): Promise<unknown> {
  const form = new FormData();
  form.append(fieldName, file);
  const res = await fetch(BASE + path, {
    method: 'POST',
    body: form,
    credentials: 'include',
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function uploadForm(path: string, form: FormData): Promise<unknown> {
  const res = await fetch(BASE + path, { method: 'POST', body: form, credentials: 'include' });
  if (res.status === 401) {
    globalThis.dispatchEvent(new Event('rt:logout'));
    throw makeApiError('Unauthorized', 401);
  }
  if (!res.ok) {
    const text = await res.text();
    let msg = text;
    let code: string | undefined;
    try {
      const parsed = JSON.parse(text) as Record<string, unknown>;
      msg = (parsed.detail as string) || (parsed.message as string) || text;
      code = parsed.code as string | undefined;
    } catch {}
    throw makeApiError(msg, res.status, code);
  }
  return res.json();
}

export async function download(path: string): Promise<Blob> {
  const res = await fetch(BASE + path, { credentials: 'include' });
  if (!res.ok) throw new Error(await res.text());
  return res.blob();
}
