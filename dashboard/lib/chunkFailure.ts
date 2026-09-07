/**
 * Is this error the signature of a tab whose JavaScript no longer exists?
 *
 * Split out of the ChunkRecovery component so the matching is unit-testable:
 * too broad and a page refresh hides real application bugs, too narrow and a
 * stale tab stays dead after a dashboard roll. Both failures are silent, which
 * is why the rule is pinned by tests.
 */
export function isChunkFailure(message: string): boolean {
  const m = message.toLowerCase();
  return (
    m.includes("chunkloaderror") ||
    m.includes("loading chunk") ||
    m.includes("loading css chunk") ||
    (m.includes("failed to fetch dynamically imported module") && m.includes("_next")) ||
    (m.includes("importing a module script failed") && m.includes("_next"))
  );
}
