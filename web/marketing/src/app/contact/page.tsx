import type { Metadata } from "next";

import { ContactForm } from "./contact-form";

/**
 * `/contact` — contact page (Task 15.3).
 *
 * Renders the {@link ContactForm} client component which submits to a
 * `console.log`-only Server Action stub (`./actions.ts`). No real
 * email transport is wired on the marketing surface yet.
 */
export const dynamic = "force-static";

export const metadata: Metadata = {
  title: "Contact",
  description:
    "Get in touch with the Xalgorix team — sales, support, and partnership inquiries.",
  alternates: { canonical: "/contact" },
};

export default function ContactPage() {
  return (
    <main id="main" className="container py-16">
      <header className="mx-auto max-w-2xl text-center">
        <p className="text-sm font-medium uppercase tracking-wide text-muted-foreground">
          Contact us
        </p>
        <h1 className="mt-2 text-balance text-4xl font-semibold tracking-tight sm:text-5xl">
          Get in touch
        </h1>
        <p className="mt-4 text-pretty text-lg text-muted-foreground">
          Questions about pricing, security review, or rolling Xalgorix
          out across your organization? Send us a note.
        </p>
      </header>

      <div className="mx-auto mt-12 max-w-2xl rounded-lg border border-border bg-card p-6 text-card-foreground sm:p-8">
        <ContactForm />
      </div>

      <p className="mx-auto mt-8 max-w-2xl text-center text-sm text-muted-foreground">
        Reporting a security issue? Please email{" "}
        <a
          href="mailto:security@xalgorix.com"
          className="font-medium text-foreground underline-offset-4 hover:underline"
        >
          security@xalgorix.com
        </a>{" "}
        directly.
      </p>
    </main>
  );
}
