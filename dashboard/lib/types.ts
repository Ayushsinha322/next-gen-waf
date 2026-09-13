// The icon is derived from `type`, not carried per toast. Call sites used to
// pass an emoji each time, so the same severity showed a different glyph
// depending on which page raised it, and a failure could arrive under a
// green tick if someone copied the wrong line.
export interface Toast { id: string; msg: string; type: "s"|"e"|"i"|"w"; }
export interface ModalConfig { title: string; body: React.ReactNode; footer: React.ReactNode; }
export interface ChatMessage { who: "ai"|"usr"; text: string; time: string; }
export interface Alert { id: number; sev: "CRITICAL"|"HIGH"|"MEDIUM"|"LOW"; time: string; ip: string; site: string; attack: string; rule: string; score: number; action: string; status: "open"|"resolved"; }
export interface Site { id: string; domain: string; upstream: string; mode: "BLOCKING"|"LEARNING"|"OFFLINE"; rules: number; rps: number; blockPct: number; status: "online"|"offline"; }
