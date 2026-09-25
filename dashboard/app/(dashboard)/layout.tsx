"use client";
import { motion, AnimatePresence } from "framer-motion";
import TopBar from "@/components/layout/TopBar";
import SideBar from "@/components/layout/SideBar";
import ToastContainer from "@/components/ui/Toast";
import ModalContainer from "@/components/ui/Modal";
import ChunkRecovery from "@/components/layout/ChunkRecovery";
import { I18nProvider } from "@/lib/i18n";

/**
 * Three things were removed from this layout and none of them should come back.
 *
 * 1. `<Ticker>` — a "LIVE THREATS" marquee that looped twelve hardcoded events
 *    (real-looking source IPs, CVE-2021-44228, a JA4 fingerprint, CRS rule ids)
 *    on every page. Nothing about it was observed traffic. For a security
 *    product this is the most damaging class of fabrication there is: it is
 *    indistinguishable from real telemetry, and a customer who later learns the
 *    threat feed was a hardcoded array will not believe the detection numbers
 *    either. Live threat activity belongs on /events, sourced from ClickHouse.
 *
 * 2. `<BgCanvas>` — a full-viewport requestAnimationFrame canvas drawing moving
 *    nodes, matrix rain and radar sweeps behind all 17 pages, composited under
 *    21 backdrop-blur surfaces. It burned GPU on every page for decoration.
 *    This was its only mount, so the component has been deleted; the login
 *    screen keeps its own separate canvas, where a brand moment is fine.
 *
 * 3. `.scanlines` — a CRT overlay. Enterprise consoles do not simulate damaged
 *    hardware.
 */
export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  return (
    <I18nProvider>
      {/* Rolling the dashboard changes every chunk filename, so a tab that was
          already open 404s on its own JavaScript and looks locked out. This
          reloads it once against the new build. */}
      <ChunkRecovery />
      <TopBar />
      <SideBar />
      <main className="content">
        <AnimatePresence mode="wait">
          <motion.div
            key={typeof window !== "undefined" ? window.location.pathname : "root"}
            initial={{ opacity: 0, y: 14 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            transition={{ duration: 0.3, ease: [0.22, 1, 0.36, 1] }}
          >
            {children}
          </motion.div>
        </AnimatePresence>
      </main>
      <ToastContainer />
      <ModalContainer />
    </I18nProvider>
  );
}