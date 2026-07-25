import type { Metadata } from "next";
import { headers } from "next/headers";
import "./globals.css";

export const metadata: Metadata = {
  title: "Next-Gen ESDS WAF — Enterprise Security Platform",
  description: "High-performance Web Application Firewall control plane",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  // Per-request CSP nonce minted in middleware.ts. The inline script below is
  // the only hand-written one in the app and needs the nonce to execute under
  // the policy; Next.js nonces the scripts it injects itself.
  const nonce = headers().get("x-nonce") ?? undefined;

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
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link
          href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;600;700;900&family=Share+Tech+Mono&family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap"
          rel="stylesheet"
        />
      </head>
      <body>{children}</body>
    </html>
  );
}
