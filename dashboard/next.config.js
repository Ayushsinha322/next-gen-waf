/** @type {import('next').NextConfig} */
const nextConfig = {
  eslint: { ignoreDuringBuilds: true },
  typescript: { ignoreBuildErrors: true },
  // Emit .next/standalone — a self-contained server with ONLY the node_modules
  // that dependency tracing proves are reachable at runtime.
  //
  // Without this the runtime image has to carry the builder's entire
  // node_modules (588 MB: TypeScript, ESLint, Tailwind, the Next compiler,
  // vitest — none of which run in production) plus .next/cache (133 MB of
  // webpack artefacts). That put the dashboard image at 779 MB against 46-55 MB
  // for the three Rust/Go images, and it alone pushed the offline bundle past
  // the ~250 MB cap this GitLab enforces on uploads, forcing the release to be
  // split into four parts and reassembled by hand on the target VM.
  //
  // Standalone changes the runner stage contract: copy .next/standalone (which
  // contains server.js and the traced deps), .next/static and public — never
  // node_modules — and start with `node server.js`, not `npm start`.
  output: "standalone",
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
        // Server-side REST proxy → internal control-plane hostname (portable).
        // NOTE: SSE (api.ts logs.streamURL) is separate and uses the *browser-
        // reachable* NEXT_PUBLIC_CONTROL_PLANE_URL, since the Next proxy buffers SSE.
        destination: (process.env.CONTROL_PLANE_URL ?? process.env.NEXT_PUBLIC_CONTROL_PLANE_URL ?? "http://localhost:9501") + "/api/v1/:path*",
      },
    ];
  },
};

module.exports = nextConfig;
