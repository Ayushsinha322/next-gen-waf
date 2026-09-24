import type { Metadata } from "next";
import { headers } from "next/headers";
import "./globals.css";
import { PRODUCT_NAME } from "@/lib/version";

export const metadata: Metadata = {
  title: `${PRODUCT_NAME} — Web Application Firewall`,
  description: "High-performance Web Application Firewall control plane",
};

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  // Per-request CSP nonce minted in middleware.ts. The inline script below is
  // the only hand-written one in the app and needs the nonce to execute under
  // the policy; Next.js nonces the scripts it injects itself.
  // `headers()` is asynchronous from Next.js 15.
  const nonce = (await headers()).get("x-nonce") ?? undefined;

  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        {/* FOUC prevention — must be first, blocking, inline */}
        <script
          nonce={nonce}
          dangerouslySetInnerHTML={{
            __html: `try{var t=localStorage.getItem('sentinel-theme')||'dark';document.documentElement.setAttribute('data-theme',t);}catch(e){}`,
          }}
        />
        {/* Two families only — Inter for the interface, JetBrains Mono for data
            and log output. Orbitron and Share Tech Mono were dropped: both are
            sci-fi display faces, and a security buyer reads them as a hobby
            project rather than infrastructure. Headings now use Inter at a
            heavier weight, which is what every enterprise console does.
            Weight 600/700 added for headings; 500 for mono emphasis. */}
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap"
          rel="stylesheet"
        />
      </head>
      <body>{children}</body>
    </html>
  );
}
