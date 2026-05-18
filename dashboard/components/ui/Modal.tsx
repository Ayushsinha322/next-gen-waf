"use client";
import { useState, useCallback, useEffect } from "react";
import type { ReactNode } from "react";

interface ModalState { title: string; body: ReactNode; footer: ReactNode; }
let openModalFn: ((s: ModalState) => void) | null = null;
export function openModal(s: ModalState) { openModalFn?.(s); }

export default function ModalContainer() {
  const [state, setState] = useState<ModalState | null>(null);
  useEffect(() => {
    openModalFn = setState;
    return () => { openModalFn = null; };
  }, []);
  const close = useCallback(() => setState(null), []);
  if (!state) return null;
  return (
    <div className="modal-bg" onClick={e => { if (e.target === e.currentTarget) close(); }}>
      <div className="modal">
        <div className="mh">
          <div className="mt2">{state.title}</div>
          <button style={{ cursor: "pointer", color: "var(--text3)", fontSize: 18, background: "none", border: "none", lineHeight: 1, transition: "color .2s" }} onClick={close}>✕</button>
        </div>
        <div className="mb">{state.body}</div>
        <div className="mf">{state.footer}</div>
      </div>
    </div>
  );
}
