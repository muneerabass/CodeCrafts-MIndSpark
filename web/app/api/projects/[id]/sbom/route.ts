import { apiUrl, mockMode, serviceToken } from '@/lib/api';
import { getCtx } from '@/lib/session';
import { mockSbom, MockNotFound } from '@/lib/mock';

// Downloads a project version's SBOM (GET /api/v1/projects/{id}/sbom) with the caller's service JWT.
export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const ctx = await getCtx();
  if (!ctx?.org) return new Response('Not found', { status: 404 });
  const { id } = await params;
  const sp = new URL(req.url).searchParams;
  const format = sp.get('format') ?? 'cyclonedx';
  if (format !== 'cyclonedx' && format !== 'spdx') return new Response('format must be cyclonedx or spdx', { status: 400 });
  const version = sp.get('version') ?? '';
  const disposition = `attachment; filename="sbom-${id.replace(/[^A-Za-z0-9_-]/g, '')}.${format === 'spdx' ? 'spdx' : 'cdx'}.json"`;

  if (mockMode) {
    try {
      return new Response(mockSbom(id, format), { headers: { 'content-type': 'application/json', 'content-disposition': disposition } });
    } catch (e) {
      return new Response('Not found', { status: e instanceof MockNotFound ? 404 : 500 });
    }
  }
  let upstream: Response;
  try {
    upstream = await fetch(apiUrl(`/api/v1/projects/${encodeURIComponent(id)}/sbom?${new URLSearchParams({ format, version })}`), {
      headers: { authorization: `Bearer ${await serviceToken()}` },
      cache: 'no-store',
      signal: AbortSignal.timeout(60_000),
    });
  } catch {
    return new Response('The depguard API is unreachable.', { status: 502 });
  }
  if (!upstream.ok) return new Response(upstream.status === 404 ? 'Not found' : 'SBOM unavailable', { status: upstream.status });
  return new Response(upstream.body, {
    headers: {
      'content-type': 'application/json',
      'content-disposition': upstream.headers.get('content-disposition') ?? disposition,
      'x-content-type-options': 'nosniff',
    },
  });
}
