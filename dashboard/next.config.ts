import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Allow proxying API calls to the control-plane in dev.
  async rewrites() {
    return [
      {
        source: "/api/v1/:path*",
        destination:
          (process.env.CONTROL_PLANE_URL ?? "http://localhost:8080") +
          "/api/v1/:path*",
      },
    ];
  },
};

export default nextConfig;
