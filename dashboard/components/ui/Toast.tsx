"use client";
import { useEffect, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Toast as ToastType } from "@/lib/types";
import { toastVariants } from "@/lib/animations";

let addToastFn: ((t: Omit<ToastType, "id">) => void) | null = null;
export function showToast(msg: string, type: ToastType["type"] = "i", icon = "ℹ️") {
  addToastFn?.({ msg, type, icon });
}

export default function ToastContainer() {
  const [toasts, setToasts] = useState<ToastType[]>([]);
  useEffect(() => {
    addToastFn = (t) => {
      const id = Math.random().toString(36).slice(2);
      setToasts(p => [...p, { ...t, id }]);
      setTimeout(() => setToasts(p => p.filter(x => x.id !== id)), 3800);
    };
    return () => { addToastFn = null; };
  }, []);

  return (
    <div style={{ position: "fixed", top: 62, right: 18, zIndex: 100, display: "flex", flexDirection: "column", gap: 8, pointerEvents: "none" }}>
      <AnimatePresence>
        {toasts.map(t => (
          <motion.div
            key={t.id}
            className={`toast ${t.type}`}
            variants={toastVariants}
            initial="hidden"
            animate="visible"
            exit="exit"
            layout
          >
            <span>{t.icon}</span>
            <span>{t.msg}</span>
          </motion.div>
        ))}
      </AnimatePresence>
    </div>
  );
}