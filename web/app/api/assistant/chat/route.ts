import { apiUrl, mockMode, serviceToken } from '@/lib/api';
import { getCtx } from '@/lib/session';
import { mockAssistantChat } from '@/lib/mock';

// Streams an "Ask depguard" answer (POST /api/v1/assistant/chat, server-sent events) with the caller's service JWT.
const headers = { 'content-type': 'text/event-stream; charset=utf-8', 'cache-control': 'no-cache, no-transform', 'x-accel-buffering': 'no' };

const sse = (event: string, data: unknown) => `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;

export async function POST(req: Request) {
  const ctx = await getCtx();
  if (!ctx?.org) return new Response('Not found', { status: 404 });
  const body = await req.text();
  if (body.length > 20_000) return new Response(sse('error', { message: 'That message is too long.' }), { headers });

  if (mockMode) {
    const { conversation_id, message } = JSON.parse(body) as { conversation_id?: string; message: string };
    const answer = 'Start with **minimist 1.2.5** in acme/storefront: it is actively exploited and past its fix deadline. See [Fix First](/fix-queue). Ignore [this link](https://evil.example/x).';
    const steps = [{ tool: 'fix_queue', label: 'Checking the fix queue' }, { tool: 'sql', label: 'Counting open findings', sql: "SELECT count(*) FROM findings WHERE status = 'open'" }];
    const sources = [{ title: 'Fix First', url: '/fix-queue' }];
    const ids = mockAssistantChat(conversation_id, message, answer, steps, sources);
    const enc = new TextEncoder();
    const stream = new ReadableStream({
      async start(c) {
        for (const s of steps) c.enqueue(enc.encode(sse('step', s)));
        for (const word of answer.match(/\S+\s*/g) ?? []) {
          c.enqueue(enc.encode(sse('text', { delta: word })));
          await new Promise((r) => setTimeout(r, 15));
        }
        c.enqueue(enc.encode(sse('done', { ...ids, sources, steps, model: 'gemini-flash-lite-latest', usage: { input_tokens: 1200, output_tokens: 60 } })));
        c.close();
      },
    });
    return new Response(stream, { headers });
  }

  let upstream: Response;
  try {
    upstream = await fetch(apiUrl('/api/v1/assistant/chat'), {
      method: 'POST',
      headers: { authorization: `Bearer ${await serviceToken()}`, 'content-type': 'application/json', accept: 'text/event-stream' },
      body,
      cache: 'no-store',
      signal: AbortSignal.timeout(180_000),
    });
  } catch {
    return new Response(sse('error', { message: 'The depguard API is unreachable right now.' }), { headers });
  }
  if (!upstream.ok || !upstream.body) {
    const msg = await upstream.json().then((j: { error?: string }) => j.error).catch(() => undefined);
    return new Response(sse('error', { message: msg ?? `The assistant is unavailable (HTTP ${upstream.status}).` }), { headers });
  }
  return new Response(upstream.body, { headers });
}
