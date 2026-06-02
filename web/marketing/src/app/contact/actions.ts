"use server";

/**
 * Server Action stub for the `/contact` form (Task 15.3).
 *
 * The marketing site does not yet wire a real email transport — the
 * production email path lives in the cloud worker (Phase 11) and is
 * gated on Resend credentials that are not provisioned for the
 * marketing surface. Until then this action validates the submitted
 * fields, logs the submission server-side via `console.log`, and
 * returns a discriminated-union result that the client component can
 * render without a page reload.
 *
 * The shape of `ContactFormState` is compatible with the React
 * `useFormState` hook so swapping in a real transport later only
 * touches the body of `submitContactForm`.
 */

export type ContactFormState =
  | { status: "idle" }
  | { status: "success"; message: string }
  | {
      status: "error";
      message: string;
      fieldErrors?: Partial<Record<"name" | "email" | "subject" | "message", string>>;
    };

export const initialContactFormState: ContactFormState = { status: "idle" };

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function asTrimmedString(value: FormDataEntryValue | null): string {
  return typeof value === "string" ? value.trim() : "";
}

export async function submitContactForm(
  _prev: ContactFormState,
  formData: FormData,
): Promise<ContactFormState> {
  const name = asTrimmedString(formData.get("name"));
  const email = asTrimmedString(formData.get("email"));
  const subject = asTrimmedString(formData.get("subject"));
  const message = asTrimmedString(formData.get("message"));

  const fieldErrors: NonNullable<
    Extract<ContactFormState, { status: "error" }>["fieldErrors"]
  > = {};

  if (name.length === 0) {
    fieldErrors.name = "Please enter your name.";
  } else if (name.length > 200) {
    fieldErrors.name = "Name must be 200 characters or fewer.";
  }

  if (email.length === 0) {
    fieldErrors.email = "Please enter your email address.";
  } else if (!EMAIL_REGEX.test(email) || email.length > 320) {
    fieldErrors.email = "Please enter a valid email address.";
  }

  if (subject.length === 0) {
    fieldErrors.subject = "Please enter a subject.";
  } else if (subject.length > 200) {
    fieldErrors.subject = "Subject must be 200 characters or fewer.";
  }

  if (message.length === 0) {
    fieldErrors.message = "Please enter a message.";
  } else if (message.length > 5000) {
    fieldErrors.message = "Message must be 5000 characters or fewer.";
  }

  if (Object.keys(fieldErrors).length > 0) {
    return {
      status: "error",
      message: "Please fix the highlighted fields and try again.",
      fieldErrors,
    };
  }

  // Stub: no real email transport is wired on the marketing surface.
  // Log server-side so the submission is visible in pod logs during
  // development and return a deterministic success response.
  // eslint-disable-next-line no-console
  console.log("[contact-form] submission received", {
    name,
    email,
    subject,
    messageLength: message.length,
  });

  return {
    status: "success",
    message: "Thanks — we received your message and will reply by email soon.",
  };
}
