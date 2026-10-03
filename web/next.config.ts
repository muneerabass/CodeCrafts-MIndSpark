import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  output: 'standalone',
  poweredByHeader: false,
  // Lets a verification build run beside a live `next start` without clobbering its .next.
  distDir: process.env.NEXT_DIST_DIR || '.next',
};

export default nextConfig;
