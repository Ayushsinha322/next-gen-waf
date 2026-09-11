import { redirect } from "next/navigation";

/**
 * The one and only owner of "/".
 *
 * There used to be two: this file, redirecting to /login, and
 * app/(dashboard)/page.tsx, redirecting to /overview. A route group adds no URL
 * segment, so both claimed the same path. Next did not fail the build — it
 * warned ("Failed to copy traced files … page_client-reference-manifest.js")
 * and shipped the (dashboard) copy WITHOUT its client manifest. Middleware
 * bounces anonymous visitors to /login before either page runs, which is why
 * curl and the unauthenticated smoke checks always saw a 307 and never the
 * fault. A logged-in browser gets past middleware, renders that manifest-less
 * page, and hits `undefined.clientModules`: a 500 on the bare root URL for
 * every authenticated user, since 17 May.
 *
 * /overview is the correct target, not /login. Middleware already redirects
 * the unauthenticated to /login, and the login page clears the session cookie
 * on mount — so sending a logged-in user there would sign them out.
 */
export default function Home() { redirect("/overview"); }
