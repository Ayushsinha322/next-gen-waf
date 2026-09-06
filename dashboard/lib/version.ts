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
