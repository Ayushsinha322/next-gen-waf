"use client";
import type { Variants, Transition } from "framer-motion";

// ── Spring configs ────────────────────────────────────────────────────────────
// Critically damped (no overshoot) — Apple's default for UI that was not flung.
export const spring: Transition = { type: "spring", duration: 0.35, bounce: 0 };
export const springSlow: Transition = { type: "spring", duration: 0.5, bounce: 0 };
// Kept for callers; a small bounce only, for motion that carries momentum.
export const springBouncy: Transition = { type: "spring", duration: 0.4, bounce: 0.12 };
export const tween: Transition = { duration: 0.2, ease: [0.2, 0.8, 0.2, 1] };
export const tweenFast: Transition = { duration: 0.14, ease: [0.2, 0.8, 0.2, 1] };

// ── Page transitions ──────────────────────────────────────────────────────────
export const pageVariants: Variants = {
  initial: { opacity: 0, y: 6 },
  enter:   { opacity: 1, y: 0, transition: { duration: 0.2, ease: [0.2, 0.8, 0.2, 1] } },
  exit:    { opacity: 0, transition: { duration: 0.12 } },
};

// ── Staggered card/fade-in ────────────────────────────────────────────────────
export const cardVariants: Variants = {
  hidden:  { opacity: 0, y: 6 },
  visible: { opacity: 1, y: 0, transition: tween },
};

export const staggerContainer: Variants = {
  hidden:  {},
  visible: { transition: { staggerChildren: 0.025, delayChildren: 0.02 } },
};

export const fadeUp: Variants = {
  hidden:  { opacity: 0, y: 6 },
  visible: { opacity: 1, y: 0, transition: tween },
};

export const fadeIn: Variants = {
  hidden:  { opacity: 0 },
  visible: { opacity: 1, transition: tween },
};

// ── Table row stagger ─────────────────────────────────────────────────────────
export const rowVariants: Variants = {
  hidden:  { opacity: 0 },
  visible: { opacity: 1, transition: tweenFast },
};

export const rowStaggerContainer: Variants = {
  hidden:  {},
  visible: { transition: { staggerChildren: 0.025 } },
};

// ── Modal ─────────────────────────────────────────────────────────────────────
export const modalOverlay: Variants = {
  hidden:  { opacity: 0 },
  visible: { opacity: 1, transition: { duration: 0.15 } },
  exit:    { opacity: 0, transition: { duration: 0.12 } },
};
export const modalPanel: Variants = {
  hidden:  { opacity: 0, scale: 0.97 },
  visible: { opacity: 1, scale: 1, transition: { ...tween, duration: 0.22 } },
  exit:    { opacity: 0, scale: 0.97, transition: { duration: 0.14 } },
};

// ── Toast ─────────────────────────────────────────────────────────────────────
export const toastVariants: Variants = {
  // Enters and leaves along the same path.
  hidden:  { opacity: 0, x: 16 },
  visible: { opacity: 1, x: 0, transition: spring },
  exit:    { opacity: 0, x: 16, transition: { duration: 0.16, ease: [0.4, 0, 1, 1] } },
};

// ── Sidebar nav items ─────────────────────────────────────────────────────────
export const navItemVariants: Variants = {
  hidden:  { opacity: 0 },
  visible: { opacity: 1, transition: { ...tween, duration: 0.18 } },
};

export const navGroupStagger: Variants = {
  hidden:  {},
  visible: { transition: { staggerChildren: 0.03, delayChildren: 0.03 } },
};

// ── Number count-up (for animated counters) ───────────────────────────────────
export const countUpVariants: Variants = {
  hidden:  { opacity: 0, y: 8 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.2, ease: [0.22, 1, 0.36, 1] } },
};
