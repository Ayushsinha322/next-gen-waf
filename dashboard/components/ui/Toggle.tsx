"use client";
import { useState } from "react";
import { motion } from "framer-motion";

export default function Toggle({ defaultOn = false }: { defaultOn?: boolean }) {
  const [on, setOn] = useState(defaultOn);
  return (
    <motion.div
      className={`tog ${on ? "on" : ""}`}
      onClick={() => setOn(!on)}
      whileTap={{ scale: 0.92 }}
    />
  );
}