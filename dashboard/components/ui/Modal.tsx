"use client";
import { useState, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import type { ReactNode } from "react";
import { toastVariants } from "@/lib/animations";

interface ModalState {
  title: string; body: ReactNode; footer: ReactNode;
  /** Called however the modal is dismissed — ✕, backdrop, Escape, or closeModal(). */
  onClose?: () => void;
}
let openModalFn: ((s: ModalState) => void) | null = null;
let closeModalFn: (() => void) | null = null;
export function openModal(s: ModalState) { openModalFn?.(s); }
export function closeModal() { closeModalFn?.(); }

export default function ModalContainer() {
  const [state, setState] = useState<ModalState | null>(null);
  const close = useCallback(() => setState(s => { s?.onClose?.(); return null; }), []);
  useEffect(() => {
    openModalFn = setState; closeModalFn = close;
    return () => { openModalFn = null; closeModalFn = null; };
  }, [close]);
  useEffect(() => {
    if (!state) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") close(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [state, close]);

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
            className="modal" role="dialog" aria-modal="true" aria-label={state.title}
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