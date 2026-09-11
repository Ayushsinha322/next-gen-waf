/**
 * The one product version string the console shows.
 *
 * Baked at build time from package.json via next.config.js; package.json is in
 * turn pinned to the repo-root VERSION file by deploy/ci/check-version-consistency.sh.
 * Never hard-code a version anywhere else in the dashboard — that is how the
 * login page, top bar and footer came to disagree with each other and with the
 * data plane.
 */
export const PRODUCT_VERSION: string = process.env.NEXT_PUBLIC_PRODUCT_VERSION ?? "dev";

/**
 * The one product name the console shows.
 *
 * Here for the same reason PRODUCT_VERSION is: the name was written out by hand
 * in six places and had already drifted — five said "Next-Gen ESDS WAF", the
 * copilot prompt said "Sentinel WAF", and the browser tab said something else
 * again. A customer reading two of those screens sees two products.
 *
 * `sentinel` stays the source codename — commands, image tags, container names,
 * log targets. It is not the product name and must not appear in the UI.
 */
export const PRODUCT_NAME = "Swaraj Kavach";
