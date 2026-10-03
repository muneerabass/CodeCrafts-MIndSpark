import { apiUrl, mockMode, serviceToken } from '@/lib/api';
import { getCtx } from '@/lib/session';

// Reverse proxy for the River UI served by the Go API at /api/v1/admin/river/*, super-admin only.
const HOP = ['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade', 'host', 'cookie', 'authorization', 'content-length', 'content-encoding'];

async function handle(req: Request, { params }: { params: Promise<{ path?: string[] }> }) {
  const ctx = await getCtx();
  if (!ctx?.sa) return new Response('Not found', { status: 404 });
  if (mockMode)
    return new Response('<!doctype html><title>River UI</title><body style="font-family:system-ui;padding:2rem"><h1>River UI</h1><p>The job queue UI is not available in mock API mode.</p></body>', {
      headers: { 'content-type': 'text/html; charset=utf-8' },
    });

  const { path = [] } = await params;
  const search = new URL(req.url).search;
  const headers = new Headers(req.headers);
  for (const h of HOP) headers.delete(h);
  headers.set('authorization', `Bearer ${await serviceToken()}`);

  let upstream: Response;
  try {
    upstream = await fetch(apiUrl(`/api/v1/admin/river/${path.map(encodeURIComponent).join('/')}${search}`), {
      method: req.method,
      headers,
      body: req.method === 'GET' || req.method === 'HEAD' ? undefined : req.body,
      redirect: 'manual',
      cache: 'no-store',
      // @ts-expect-error -- Node fetch needs duplex for streamed request bodies; not in the DOM RequestInit type.
      duplex: 'half',
    });
  } catch {
    return new Response('The depguard API is unreachable.', { status: 502 });
  }
  const out = new Headers(upstream.headers);
  for (const h of HOP) out.delete(h);
  out.delete('set-cookie');
  return new Response(upstream.body, { status: upstream.status, statusText: upstream.statusText, headers: out });
}

export { handle as GET, handle as POST, handle as PUT, handle as PATCH, handle as DELETE, handle as HEAD };
