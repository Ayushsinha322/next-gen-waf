import { log, getReqHeader, setDecision, addScore, setResponseHeader, Decision } from "../../sdk-assemblyscript/sentinel";

export function evaluate(): void {
  log("Hello from AssemblyScript plugin!");

  let ua = getReqHeader("user-agent");
  if (ua == null) {
    log("No User-Agent header — suspicious");
    addScore(2);
  } else if (ua.includes("sqlmap")) {
    log("SQLMap detected in User-Agent");
    setDecision(Decision.Block);
  }

  setResponseHeader("X-Sentinel-Plugin", "hello-world-as/v0.1.0");
}