/**
 * JSON-LD structured data emitter.
 *
 * Renders a `<script type="application/ld+json">` tag whose contents are
 * the JSON serialisation of the supplied payload. This is a *server*
 * component (no `"use client"` directive) so the payload lands in the
 * server-rendered HTML where search engine crawlers can read it without
 * executing JavaScript.
 *
 * Implements Requirement 2.5:
 *
 *   "WHEN a visitor requests a Marketing_Site page, THE Marketing_Site
 *    SHALL respond with a 200 status code and HTML containing valid
 *    JSON-LD `Organization` and `Product` schema in the document head."
 *
 * The payload is serialised via `JSON.stringify` and emitted using
 * `dangerouslySetInnerHTML`. We deliberately bypass React's automatic
 * text-escaping here because:
 *
 *   1. The payload is data, not user-supplied markup. Callers in this
 *      package pass static schema.org descriptors (Organization, Product,
 *      Offer) so there is no XSS surface.
 *   2. React's default text node escaping turns characters such as `"`
 *      into `&quot;`, which Google's structured-data parsers reject.
 *      The `application/ld+json` script body MUST be valid JSON.
 *
 * If a future caller ever wires user-controllable input into a JSON-LD
 * payload, that caller must sanitise its inputs at the call site. This
 * component intentionally trusts its caller.
 */
import type { ReactElement } from "react";

/**
 * Schema.org-shaped object. The shape varies by `@type` so we accept a
 * loose `Record<string, unknown>` rather than constraining consumers to
 * a particular schema.
 */
export type JsonLdPayload = Record<string, unknown>;

export interface JsonLdProps {
  /** The schema.org payload to serialise. */
  data: JsonLdPayload;
}

export function JsonLd({ data }: JsonLdProps): ReactElement {
  return (
    <script
      type="application/ld+json"
      dangerouslySetInnerHTML={{ __html: JSON.stringify(data) }}
    />
  );
}
