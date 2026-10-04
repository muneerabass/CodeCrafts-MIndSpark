import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  output: 'standalone',
  poweredByHeader: false,
  // Lets a verification build run beside a live `next start` without clobbering its .next.
  distDir: process.env.NEXT_DIST_DIR || '.next',
  // Vault uploads carry encrypted files (up to ~1.4 MB each); a key rotation re-sends every item at once.
  experimental: { serverActions: { bodySizeLimit: '32mb' } },
};

export default nextConfig;
