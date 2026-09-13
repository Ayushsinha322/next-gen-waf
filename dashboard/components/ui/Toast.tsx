"use client";
import { useEffect, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Toast as ToastType } from "@/lib/types";
import { toastVariants } from "@/lib/animations";
import Icon, { type IconName } from "@/components/ui/Icon";

let addToastFn: ((t: Omit<ToastType, "id">) => void) | null = null;

/**
 * Raise a toast.
 *
 * There is deliberately no icon argument. Every call site used to pass its own
 * emoji, which meant the same severity looked different on every page and an
 * error could be announced under a green tick. The icon now follows the
 * severity, so it cannot disagree with the colour.
 */
export function showToast(msg: string, type: ToastType["type"] = "i") {
  addToastFn?.({ msg, type });
}

const SEVERITY_ICON: Record<ToastType["type"], IconName> = {
  s: "check-circle",
  e: "alert-triangle",
  w: "alert-circle",
  i: "info",
};

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
            <Icon name={SEVERITY_ICON[t.type]} size={15} />
            <span>{t.msg}</span>
          </motion.div>
        ))}
      </AnimatePresence>
    </div>
  );
}