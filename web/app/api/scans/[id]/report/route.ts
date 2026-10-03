import { apiUrl, mockMode, serviceToken } from '@/lib/api';
import { getCtx } from '@/lib/session';
import { mockReport, MockNotFound } from '@/lib/mock';

// Downloads the combined scan report (GET /api/v1/scans/{id}/report) with the caller's service JWT.
const TYPES = { md: 'text/markdown; charset=utf-8', json: 'application/json', html: 'text/html; charset=utf-8' } as const;
type Format = keyof typeof TYPES;

export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const ctx = await getCtx();
  if (!ctx?.org) return new Response('Not found', { status: 404 });
  const { id } = await params;
  const format = (new URL(req.url).searchParams.get('format') ?? 'md') as Format;
  if (!Object.hasOwn(TYPES, format)) return new Response('format must be md, json or html', { status: 400 });
  const disposition = `attachment; filename="depguard-report-${id.replace(/[^A-Za-z0-9_-]/g, '')}.${format}"`;

  if (mockMode) {
    try {
      return new Response(mockReport(id, format), { headers: { 'content-type': TYPES[format], 'content-disposition': disposition } });
    } catch (e) {
      return new Response('Not found', { status: e instanceof MockNotFound ? 404 : 500 });
    }
  }

  let upstream: Response;
  try {
    upstream = await fetch(apiUrl(`/api/v1/scans/${encodeURIComponent(id)}/report?format=${format}`), {
      headers: { authorization: `Bearer ${await serviceToken()}` },
      cache: 'no-store',
      signal: AbortSignal.timeout(30_000),
    });
  } catch {
    return new Response('The depguard API is unreachable.', { status: 502 });
  }
  if (!upstream.ok) return new Response(upstream.status === 404 ? 'Not found' : 'Report unavailable', { status: upstream.status });
  return new Response(upstream.body, {
    headers: {
      'content-type': upstream.headers.get('content-type') ?? TYPES[format],
      'content-disposition': upstream.headers.get('content-disposition') ?? disposition,
      'x-content-type-options': 'nosniff',
    },
  });
}
