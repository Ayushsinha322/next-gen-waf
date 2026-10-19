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

// ── Destructive actions elsewhere in the console ──────────────────────────────
// These used the browser's native confirm(): a grey system box that blocks the
// whole page, cannot say what happens next in the product's own words, and on
// some browsers can be suppressed for the rest of the session with a checkbox.

export function ruleDeleteConfirm(name: string): ConfirmOptions {
  return {
    title: `Delete rule "${name}"?`,
    body: "Every site stops evaluating it within about 5 seconds. Disabling the rule instead keeps it for later.",
    confirmLabel: "Delete rule",
    tone: "danger",
  };
}

export function ipBlockEverywhereConfirm(ip: string): ConfirmOptions {
  return {
    title: `Block ${ip} on every site?`,
    body: "Adds a manual block-tier indicator to the threat-intel feed, so every site this WAF protects refuses this address within about 5 seconds. Remove it from Threat Intel to unblock.",
    confirmLabel: `Block ${ip} everywhere`,
    tone: "danger",
  };
}

export function certDeleteConfirm(domain: string): ConfirmOptions {
  return {
    title: `Delete the certificate for ${domain}?`,
    body: "The site falls back to a self-signed certificate, so visitors' browsers show a security warning until a valid certificate is added again.",
    confirmLabel: "Delete certificate",
    tone: "danger",
  };
}

export function apiKeyRevokeConfirm(name: string): ConfirmOptions {
  return {
    title: `Revoke API key "${name}"?`,
    body: "Anything still using this key — scripts, CI jobs, integrations — is refused from now on. This cannot be undone; a new key would have to be created and distributed.",
    confirmLabel: "Revoke key",
    tone: "danger",
  };
}

export function channelDeleteConfirm(name: string): ConfirmOptions {
  return {
    title: `Delete channel "${name}"?`,
    body: "Alerts and scheduled reports that use this channel stop being delivered to it.",
    confirmLabel: "Delete channel",
    tone: "danger",
  };
}

export function mgmtCertRevertConfirm(): ConfirmOptions {
  return {
    title: "Revert to the self-signed management certificate?",
    body: "The console goes back to the built-in self-signed certificate, so browsers warn on the next visit until they trust it again.",
    confirmLabel: "Revert certificate",
    tone: "warn",
  };
}

export function iocRemoveConfirm(type: string, value: string): ConfirmOptions {
  return {
    title: `Remove this ${type} indicator?`,
    body: `"${value}" is taken out of the threat-intel feed. If it was a block-tier indicator, traffic matching it is no longer refused by that indicator.`,
    confirmLabel: "Remove indicator",
    tone: "warn",
  };
}

export function pluginDeleteConfirm(name: string): ConfirmOptions {
  return {
    title: `Delete plugin "${name}"?`,
    body: "It is removed from every WAF node on the next sync, and every site using it stops running it. Reinstalling needs the original .zip.",
    confirmLabel: "Delete plugin",
    tone: "danger",
  };
}

export function reportScheduleDeleteConfirm(name: string): ConfirmOptions {
  return {
    title: `Delete the schedule "${name}"?`,
    body: "No further reports are sent on this schedule. Reports already delivered are unaffected.",
    confirmLabel: "Delete schedule",
    tone: "warn",
  };
}

export function logProfileDeleteConfirm(name: string): ConfirmOptions {
  return {
    title: `Delete the log profile "${name}"?`,
    body: "The saved filter is removed. No logs are deleted.",
    confirmLabel: "Delete profile",
    tone: "warn",
  };
}
