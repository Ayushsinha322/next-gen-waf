"use client";
import { useState, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import type { ReactNode } from "react";
import { toastVariants } from "@/lib/animations";

interface ModalState { title: string; body: ReactNode; footer: ReactNode; }
let openModalFn: ((s: ModalState) => void) | null = null;
export function openModal(s: ModalState) { openModalFn?.(s); }

export default function ModalContainer() {
  const [state, setState] = useState<ModalState | null>(null);
  useEffect(() => { openModalFn = setState; return () => { openModalFn = null; }; }, []);
  const close = useCallback(() => setState(null), []);

  return (
    <AnimatePresence>
      {state && (
        <motion.div
          className="modal-bg"
          onClick={e => { if (e.target === e.currentTarget) close(); }}
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.2 }}
        >
          <motion.div
            className="modal"
            initial={{ opacity: 0, scale: 0.94, y: 14 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.96, y: 8 }}
            transition={{ type: "spring", stiffness: 280, damping: 24 }}
          >
            <div className="mh">
              <div className="mt2">{state.title}</div>
              <button style={{ cursor: "pointer", color: "var(--text3)", fontSize: 20, background: "none", border: "none", lineHeight: 1, transition: "color .2s" }} onClick={close}>✕</button>
            </div>
            <div className="mb">{state.body}</div>
            <div className="mf">{state.footer}</div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}