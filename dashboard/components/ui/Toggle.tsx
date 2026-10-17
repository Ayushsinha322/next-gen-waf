"use client";
import { useState } from "react";
import { motion } from "framer-motion";

export default function Toggle({
  defaultOn = false,
  onChange,
}: {
  defaultOn?: boolean;
  /** Called with the new state when toggled. The flip is optimistic; if this
   *  throws or rejects (e.g. the backend save fails) the toggle rolls back to
   *  its previous state. */
  onChange?: (on: boolean) => void | Promise<void>;
}) {
  const [on, setOn] = useState(defaultOn);
  return (
    <motion.div
      className={`tog ${on ? "on" : ""}`}
      onClick={async () => {
        const next = !on;
        setOn(next); // optimistic
        try {
          await onChange?.(next);
        } catch {
          setOn(!next); // persistence failed — roll back
        }
      }}
      whileTap={{ scale: 0.97 }}
    />
  );
}