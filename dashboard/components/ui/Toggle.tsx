"use client";
import { useState } from "react";
export default function Toggle({ defaultOn = false }: { defaultOn?: boolean }) {
  const [on, setOn] = useState(defaultOn);
  return <div className={`tog ${on ? "on" : ""}`} onClick={() => setOn(!on)} />;
}
