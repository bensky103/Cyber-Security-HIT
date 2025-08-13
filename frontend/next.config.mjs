/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  eslint: {
    ignoreDuringBuilds: true,
  },
  typescript: {
    ignoreBuildErrors: true,
  },
  images: {
    unoptimized: true,
  },
  async rewrites() {
    // Proxy API calls to the Flask backend to avoid CORS in dev/prod
    // Configure BACKEND_ORIGIN (e.g., http://localhost:5000)
    const backend = process.env.BACKEND_ORIGIN || 'http://localhost:5000'
    return [
      {
        source: '/api/:path*',
        destination: `${backend}/:path*`,
      },
    ]
  },
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff',
          },
          {
            key: 'X-Frame-Options',
            value: 'DENY',
          },
          {
            key: 'Referrer-Policy',
            value: 'strict-origin-when-cross-origin',
          },
        ],
      },
    ];
  },
  // Dev warmup: run once after the dev server starts to precompile common pages
  experimental: {
    serverActions: {
      bodySizeLimit: '2mb',
    },
  },
};

// Hook for dev: Next doesn't expose a direct onListen, so we rely on a small delay
if (process.env.NODE_ENV === 'development') {
  // dynamic import to avoid affecting prod
  import('./scripts/dev-warmup.mjs')
    .then((m) => m.runWarmup && m.runWarmup())
    .catch(() => {})
}

export default nextConfig;
