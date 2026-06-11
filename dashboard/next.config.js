/** @type {import('next').NextConfig} */
const nextConfig = {
  eslint: { ignoreDuringBuilds: true },
  typescript: { ignoreBuildErrors: true },
  // Prevents stale webpack chunk errors ("Cannot find module './NNN.js'")
  // by assigning stable deterministic chunk IDs based on content hash.
  webpack: (config, { dev, isServer }) => {
    if (!dev) {
      config.optimization = {
        ...config.optimization,
        moduleIds: "deterministic",
        chunkIds: "deterministic",
      };
    }
    return config;
  },
  // Generate a fresh build ID on every start so old cached chunks are never referenced
  generateBuildId: async () => `build-${Date.now()}`,
  async rewrites() {
    return [
      {
        source: "/api/v1/:path*",
        destination: (process.env.NEXT_PUBLIC_CONTROL_PLANE_URL ?? process.env.CONTROL_PLANE_URL ?? "http://localhost:9501") + "/api/v1/:path*",
      },
    ];
  },
};

module.exports = nextConfig;
