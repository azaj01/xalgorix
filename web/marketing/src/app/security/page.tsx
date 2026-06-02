import type { Metadata } from "next";
import Link from "next/link";

import { buttonVariants } from "@xalgorix/ui";

/**
 * `/security` — security overview (Task 15.3).
 *
 * Per the design's "Decisions and Defaults" section and Requirement 20:
 *   - SOC 2 Type II is "in progress" (no certification yet);
 *   - data at rest uses AES-256-GCM with envelope encryption;
 *   - all data in transit uses TLS 1.3;
 *   - KMS key material is rotated every 90 days (Task 14.5);
 *   - vulnerability reports are accepted at the documented mailto.
 */
export const dynamic = "force-static";

const SECURITY_CONTACT = "security@xalgorix.com";

export const metadata: Metadata = {
  title: "Security",
  description:
    "How Xalgorix protects customer data: SOC 2 progress, AES-256-GCM encryption at rest, TLS 1.3 in transit, 90-day KMS rotation, and our vulnerability disclosure process.",
  alternates: { canonical: "/security" },
};

type Section = {
  id: string;
  title: string;
  body: string;
};

const SECTIONS: readonly Section[] = [
  {
    id: "soc2",
    title: "SOC 2 progress",
    body: "Xalgorix is actively working toward SOC 2 Type II attestation. Independent audit fieldwork is in progress and the report will be made available to customers under NDA on request once the audit window closes. Until then, our control narrative, sub-processor list, and gap analysis are available to customers on Pro and Enterprise plans.",
  },
  {
    id: "encryption-at-rest",
    title: "AES-256-GCM at rest",
    body: "All customer data — Postgres rows, S3-compatible object storage, backups, and message-queue state — is encrypted at rest with AES-256-GCM. Object data is wrapped per-tenant via envelope encryption: the data key is encrypted with a customer-region KMS master key, and the cipher text is stored alongside the AES-GCM authentication tag.",
  },
  {
    id: "encryption-in-transit",
    title: "TLS 1.3 in transit",
    body: "Every connection that crosses a network boundary — public APIs, the dashboard, internal service-to-service calls, and the WebSocket scan-event stream — uses TLS 1.3 with modern AEAD cipher suites. HTTP Strict Transport Security with preload is enforced on xalgorix.com and every subdomain. Plain HTTP is rejected at the edge.",
  },
  {
    id: "key-rotation",
    title: "90-day KMS key rotation",
    body: "KMS master keys backing envelope encryption are rotated automatically every 90 days. Old key versions remain available for unwrapping previously stored data keys and are retired only after re-wrap is complete. The rotation policy is enforced by infrastructure-as-code and audited as part of our daily security workflow.",
  },
  {
    id: "disclosure",
    title: "Vulnerability disclosure",
    body: "If you believe you have found a vulnerability in Xalgorix, please report it privately. We acknowledge reports within one business day and aim to remediate confirmed high-severity issues within 30 days. We do not pursue legal action against good-faith researchers who comply with our disclosure policy.",
  },
];

export default function SecurityPage() {
  return (
    <main id="main" className="container py-16">
      <header className="mx-auto max-w-2xl text-center">
        <p className="text-sm font-medium uppercase tracking-wide text-muted-foreground">
          Trust and security
        </p>
        <h1 className="mt-2 text-balance text-4xl font-semibold tracking-tight sm:text-5xl">
          Security at Xalgorix
        </h1>
        <p className="mt-4 text-pretty text-lg text-muted-foreground">
          We build a security platform, so we take our own security seriously.
          This page summarizes the controls that protect your data today.
        </p>
      </header>

      <nav
        aria-label="On this page"
        className="mx-auto mt-12 max-w-3xl rounded-lg border border-border bg-card p-4 text-sm text-card-foreground"
      >
        <p className="font-medium">On this page</p>
        <ul className="mt-2 grid gap-1 sm:grid-cols-2">
          {SECTIONS.map((section) => (
            <li key={section.id}>
              <a
                href={`#${section.id}`}
                className="text-muted-foreground hover:text-foreground"
              >
                {section.title}
              </a>
            </li>
          ))}
        </ul>
      </nav>

      <div className="mx-auto mt-12 max-w-3xl space-y-12">
        {SECTIONS.map((section) => (
          <section key={section.id} id={section.id} aria-labelledby={`${section.id}-heading`}>
            <h2
              id={`${section.id}-heading`}
              className="text-2xl font-semibold tracking-tight"
            >
              {section.title}
            </h2>
            <p className="mt-3 text-pretty text-muted-foreground">
              {section.body}
            </p>
          </section>
        ))}

        <section
          aria-labelledby="report-heading"
          className="rounded-lg border border-border bg-card p-6 text-card-foreground"
        >
          <h2
            id="report-heading"
            className="text-xl font-semibold tracking-tight"
          >
            Report a vulnerability
          </h2>
          <p className="mt-2 text-pretty text-muted-foreground">
            Email{" "}
            <a
              href={`mailto:${SECURITY_CONTACT}`}
              className="font-medium text-foreground underline-offset-4 hover:underline"
            >
              {SECURITY_CONTACT}
            </a>{" "}
            with a clear description, reproduction steps, and your contact
            details. PGP-encrypted reports are welcome on request.
          </p>
          <div className="mt-4">
            <Link
              href={`mailto:${SECURITY_CONTACT}?subject=Vulnerability%20report`}
              className={buttonVariants({ variant: "outline" })}
            >
              Email {SECURITY_CONTACT}
            </Link>
          </div>
        </section>
      </div>
    </main>
  );
}
