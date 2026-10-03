# syntax=docker/dockerfile:1
FROM node:22-alpine AS base
RUN corepack enable
WORKDIR /app

FROM base AS deps
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile

FROM base AS build
COPY --from=deps /app/node_modules ./node_modules
COPY . .
# NEXT_PUBLIC_* values are inlined into the client bundle during `pnpm build`,
# so they must be supplied as build args (see deploy/compose.yml). The Supabase
# service-role key is deliberately NOT a build arg — it only reaches the
# runtime stage via environment variables.
ARG NEXT_PUBLIC_SUPABASE_URL
ARG NEXT_PUBLIC_SUPABASE_ANON_KEY
ARG NEXT_PUBLIC_SUPABASE_GITHUB_ENABLED=1
ARG NEXT_PUBLIC_SUPABASE_GOOGLE_ENABLED=0
ENV NEXT_TELEMETRY_DISABLED=1 \
    NEXT_PUBLIC_SUPABASE_URL=${NEXT_PUBLIC_SUPABASE_URL} \
    NEXT_PUBLIC_SUPABASE_ANON_KEY=${NEXT_PUBLIC_SUPABASE_ANON_KEY} \
    NEXT_PUBLIC_SUPABASE_GITHUB_ENABLED=${NEXT_PUBLIC_SUPABASE_GITHUB_ENABLED} \
    NEXT_PUBLIC_SUPABASE_GOOGLE_ENABLED=${NEXT_PUBLIC_SUPABASE_GOOGLE_ENABLED}
# Placeholder only satisfies Better Auth while collecting page data; the runtime stage never sees it.
RUN BETTER_AUTH_SECRET=build-only-placeholder-not-used-at-runtime-0000 pnpm build

# Migrations image target: `docker build --target migrate` then run with DATABASE_URL_WEB set.
FROM build AS migrate
CMD ["pnpm", "exec", "drizzle-kit", "migrate"]

FROM node:22-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 PORT=3000 HOSTNAME=0.0.0.0
RUN addgroup -S -g 1001 nodejs && adduser -S -u 1001 -G nodejs nextjs
COPY --from=build --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=build --chown=nextjs:nodejs /app/.next/static ./.next/static
COPY --from=build --chown=nextjs:nodejs /app/public ./public
USER nextjs
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD wget -qO- "http://127.0.0.1:${PORT:-3000}/sign-in" >/dev/null || exit 1
CMD ["node", "server.js"]
