import type { ConfirmOptions } from "@/components/ui/confirm";

/**
 * The questions asked before actions that change what protects a site. Each says
 * the consequence in plain words — what visitors and attackers will experience —
 * because the mode names alone ("off", "blocking") did not stop an operator from
 * switching the wrong one in a single click.
 */
export function modeChangeConfirm(site: string, from: string, to: string): ConfirmOptions {
  switch (to) {
    case "off":
      return {
        title: `Turn protection OFF for ${site}?`,
        body: "Every request — attacks included — is forwarded to the application without inspection, and nothing is recorded. Use Learning instead if you only want to stop blocking.",
        confirmLabel: "Turn protection off",
        tone: "danger",
      };
    case "blocking":
      return {
        title: `Start blocking on ${site}?`,
        body: "From about 5 seconds from now, requests the rules judge to be attacks get a 403 and never reach the application. Check the site's learning report for would-block events on real traffic first — each one is a request that will now be refused.",
        confirmLabel: "Start blocking",
        tone: "warn",
      };
    default:
      return {
        title: from === "blocking" ? `Stop blocking on ${site}?` : `Switch ${site} to Learning?`,
        body: from === "blocking"
          ? "Attacks will reach the application. They are still inspected and recorded as would-block, but nothing is refused."
          : "Requests are inspected and recorded as would-block; nothing is refused.",
        confirmLabel: "Switch to Learning",
        tone: from === "blocking" ? "danger" : "warn",
      };
  }
}

export function pauseConfirm(site: string, domains: string[]): ConfirmOptions {
  return {
    title: `Pause ${site}?`,
    body: `The WAF stops serving ${domains.join(", ") || "this site"}: visitors get an error instead of the application until the site is activated again. To keep the application up without blocking, switch to Learning instead.`,
    confirmLabel: "Pause site",
    tone: "danger",
  };
}

export function deleteConfirm(site: string, domains: string[]): ConfirmOptions {
  return {
    title: `Delete ${site}?`,
    body: `${domains.join(", ") || "Its domains"} will no longer be served by the WAF, and the site's configuration is removed. This cannot be undone.`,
    confirmLabel: "Delete site",
    tone: "danger",
  };
}

export function countryBlockConfirm(country: string): ConfirmOptions {
  return {
    title: `Block ${country} on every site?`,
    body: `Requests from ${country} are refused on EVERY site this WAF protects, not only the one you are looking at — including customers and staff travelling there. To block it for one site, use that site's Geo & IP settings.`,
    confirmLabel: `Block ${country} everywhere`,
    tone: "danger",
  };
}
