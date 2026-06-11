"use client";
import type { Variants, Transition } from "framer-motion";

// ── Spring configs ────────────────────────────────────────────────────────────
export const spring: Transition = { type: "spring", stiffness: 420, damping: 30 };
export const springSlow: Transition = { type: "spring", stiffness: 280, damping: 28 };
export const springBouncy: Transition = { type: "spring", stiffness: 500, damping: 20 };
export const tween: Transition = { duration: 0.18, ease: [0.22, 1, 0.36, 1] };
export const tweenFast: Transition = { duration: 0.15, ease: [0.22, 1, 0.36, 1] };

// ── Page transitions ──────────────────────────────────────────────────────────
export const pageVariants: Variants = {
  initial: { opacity: 0, y: 10 },
  enter:   { opacity: 1, y: 0, transition: { duration: 0.2, ease: [0.22, 1, 0.36, 1] } },
  exit:    { opacity: 0, y: -6, transition: { duration: 0.15 } },
};

// ── Staggered card/fade-in ────────────────────────────────────────────────────
export const cardVariants: Variants = {
  hidden:  { opacity: 0, y: 16, scale: 0.97 },
  visible: { opacity: 1, y: 0, scale: 1, transition: tween },
};

export const staggerContainer: Variants = {
  hidden:  {},
  visible: { transition: { staggerChildren: 0.04, delayChildren: 0.05 } },
};

export const fadeUp: Variants = {
  hidden:  { opacity: 0, y: 10 },
  visible: { opacity: 1, y: 0, transition: tween },
};

export const fadeIn: Variants = {
  hidden:  { opacity: 0 },
  visible: { opacity: 1, transition: tween },
};

// ── Table row stagger ─────────────────────────────────────────────────────────
export const rowVariants: Variants = {
  hidden:  { opacity: 0, x: -6 },
  visible: { opacity: 1, x: 0, transition: tweenFast },
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
  hidden:  { opacity: 0, scale: 0.96, y: 10 },
  visible: { opacity: 1, scale: 1, y: 0, transition: { ...tween, duration: 0.2 } },
  exit:    { opacity: 0, scale: 0.97, y: 6, transition: { duration: 0.12 } },
};

// ── Toast ─────────────────────────────────────────────────────────────────────
export const toastVariants: Variants = {
  hidden:  { opacity: 0, x: 16, scale: 0.96 },
  visible: { opacity: 1, x: 0, scale: 1, transition: spring },
  exit:    { opacity: 0, x: 14, transition: { duration: 0.15 } },
};

// ── Sidebar nav items ─────────────────────────────────────────────────────────
export const navItemVariants: Variants = {
  hidden:  { opacity: 0, x: -10 },
  visible: { opacity: 1, x: 0, transition: { ...tween, duration: 0.18 } },
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
