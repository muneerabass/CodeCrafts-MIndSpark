import { defineConfig, devices } from '@playwright/test';

const PORT = Number(process.env.E2E_PORT ?? 3100);

// Runs against `next dev` with fixtures (MOCK_API=1) and the dev-only auth bypass.
export default defineConfig({
  testDir: './e2e',
  timeout: 60_000,
  expect: { timeout: 15_000 },
  fullyParallel: false,
  workers: 1,
  reporter: [['list']],
  use: { baseURL: `http://localhost:${PORT}`, trace: 'retain-on-failure' },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: `pnpm exec next dev -p ${PORT}`,
    url: `http://localhost:${PORT}/sign-in`,
    reuseExistingServer: true,
    timeout: 180_000,
    env: {
      MOCK_API: '1',
      E2E_AUTH_BYPASS: '1',
      SERVICE_JWT_SECRET: 'e2e-not-a-secret',
      // Pin everything the app reads so a developer's web/.env.local can't leak in.
      TENANT_DOMAIN_SUFFIX: 'depguard.dev',
      PUBLIC_URL: `http://localhost:${PORT}`,
      PUBLIC_API_URL: 'https://api.depguard.dev',
      SUPERADMIN_EMAILS: 'ada@acme.dev',
      NEXT_PUBLIC_SUPABASE_URL: 'https://e2e.invalid.supabase.co',
      NEXT_PUBLIC_SUPABASE_ANON_KEY: 'e2e-anon',
      SUPABASE_SERVICE_ROLE_KEY: 'e2e-service-role',
    },
  },
});
