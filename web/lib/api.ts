import 'server-only';
import { SignJWT } from 'jose';
import { notFound } from 'next/navigation';
import { getCtx } from './session';
import { mockApi, MockNotFound } from './mock';

const API_URL = (process.env.API_URL ?? 'http://localhost:8080').replace(/\/$/, '');
export const mockMode = process.env.MOCK_API === '1';

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

type Opts = {
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  query?: Record<string, string | number | boolean | undefined | null>;
  body?: unknown;
};

/** Short-lived service JWT carrying the caller's tenant, user, role and super-admin flag. */
export async function serviceToken() {
  const ctx = await getCtx();
  const secret = process.env.SERVICE_JWT_SECRET;
  if (!secret || secret.length < 32) throw new ApiError(500, 'SERVICE_JWT_SECRET must be set (at least 32 characters)');
  return new SignJWT({
    tid: ctx?.org?.id ?? '',
    uid: ctx?.user.id ?? '',
    role: ctx?.role ?? '',
    sa: !!ctx?.sa,
    email: ctx?.user.email ?? '',
    name: ctx?.user.name ?? '',
  })
    .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
    .setIssuedAt()
    .setExpirationTime('60s')
    .sign(new TextEncoder().encode(secret));
}

export function apiUrl(path: string) {
  return `${API_URL}${path}`;
}

/** Calls the Go API (`/api/v1` + path) on behalf of the signed-in user. Server-only. */
export async function api<T>(path: string, opts: Opts = {}): Promise<T> {
  const method = opts.method ?? 'GET';
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(opts.query ?? {})) if (v !== undefined && v !== null && v !== '') qs.set(k, String(v));

  if (mockMode) {
    try {
      return structuredClone(mockApi(method, path, qs, opts.body)) as T;
    } catch (e) {
      if (e instanceof MockNotFound) throw new ApiError(404, e.message || 'not found');
      throw new ApiError(400, (e as Error).message);
    }
  }

  let res: Response;
  try {
    res = await fetch(`${API_URL}/api/v1${path}${qs.size ? `?${qs}` : ''}`, {
      method,
      cache: 'no-store',
      headers: {
        authorization: `Bearer ${await serviceToken()}`,
        ...(opts.body !== undefined && { 'content-type': 'application/json' }),
      },
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
      signal: AbortSignal.timeout(15_000),
    });
  } catch {
    throw new ApiError(503, 'The depguard API is unreachable.');
  }
  if (!res.ok) {
    const msg = await res.json().then((j: { error?: string }) => j.error).catch(() => undefined);
    throw new ApiError(res.status, msg ?? `API error ${res.status}`);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

/** Like api(), but a 404 renders the Next.js not-found page. */
export async function apiOr404<T>(path: string, opts?: Opts): Promise<T> {
  try {
    return await api<T>(path, opts);
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) notFound();
    throw e;
  }
}

/** Pass-through of list query params from the page URL (page, page_size and filters). */
export function listQuery(sp: SP, keys: string[], pageSize = 20) {
  const q: Record<string, string> = { page: one(sp.page) ?? '1', page_size: one(sp.page_size) ?? String(pageSize) };
  for (const k of keys) {
    const v = one(sp[k]);
    if (v) q[k] = v;
  }
  return q;
}
export type SP = Record<string, string | string[] | undefined>;
export type SearchParams = Promise<SP>;
export const one = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v);

/**
 * True when a super-admin disabled the active tenant. Reads `disabled_at` from GET /settings, and also treats a
 * 403 mentioning "disabled" as disabled (API-side check). Any other failure is left to the page's error boundary.
 */
export async function tenantDisabled(): Promise<boolean> {
  try {
    return !!(await api<{ disabled_at?: string | null }>('/settings')).disabled_at;
  } catch (e) {
    return e instanceof ApiError && e.status === 403 && /disabled/i.test(e.message);
  }
}
