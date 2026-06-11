"use client";
import { motion, AnimatePresence } from "framer-motion";
import BgCanvas from "@/components/canvas/BgCanvas";
import TopBar from "@/components/layout/TopBar";
import SideBar from "@/components/layout/SideBar";
import Ticker from "@/components/layout/Ticker";
import ToastContainer from "@/components/ui/Toast";
import ModalContainer from "@/components/ui/Modal";
import CopilotFab from "@/components/copilot/CopilotFab";

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  return (
    <>
      <BgCanvas opacity={0.35} />
      <div className="scanlines" />
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
      <Ticker className="ticker-bar" />
      <CopilotFab variant="dashboard" />
      <ToastContainer />
      <ModalContainer />
    </>
  );
}