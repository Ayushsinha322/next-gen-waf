"use client";
import { useState } from "react";
import { motion } from "framer-motion";

export default function Toggle({
  defaultOn = false,
  onChange,
}: {
  defaultOn?: boolean;
  /** Called with the new state when toggled. When provided, the component is
   *  still visually optimistic but the caller drives the real state. */
  onChange?: (on: boolean) => void;
}) {
  const [on, setOn] = useState(defaultOn);
  return (
    <motion.div
      className={`tog ${on ? "on" : ""}`}
      onClick={() => { const next = !on; setOn(next); onChange?.(next); }}
      whileTap={{ scale: 0.92 }}
    />
  );
}