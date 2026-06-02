"use client";

/**
 * Client component for the `/contact` form (Task 15.3).
 *
 * Uses React's progressive-enhancement primitives (`useFormState` +
 * `useFormStatus`) so the form submits as a regular POST without
 * JavaScript and upgrades to inline error/success messaging when the
 * client bundle hydrates.
 */
import { useFormState, useFormStatus } from "react-dom";

import { Button } from "@xalgorix/ui";

import {
  initialContactFormState,
  submitContactForm,
  type ContactFormState,
} from "./actions";

function fieldError(state: ContactFormState, field: string): string | undefined {
  if (state.status !== "error" || !state.fieldErrors) return undefined;
  return state.fieldErrors[field as keyof typeof state.fieldErrors];
}

function SubmitButton() {
  const { pending } = useFormStatus();
  return (
    <Button type="submit" disabled={pending} aria-disabled={pending}>
      {pending ? "Sending…" : "Send message"}
    </Button>
  );
}

export function ContactForm() {
  const [state, formAction] = useFormState(
    submitContactForm,
    initialContactFormState,
  );

  const nameError = fieldError(state, "name");
  const emailError = fieldError(state, "email");
  const subjectError = fieldError(state, "subject");
  const messageError = fieldError(state, "message");

  return (
    <form
      action={formAction}
      noValidate
      className="space-y-6"
      aria-describedby={
        state.status === "error" ? "contact-form-error" : undefined
      }
    >
      {state.status === "success" ? (
        <p
          role="status"
          className="rounded-md border border-border bg-card p-4 text-sm text-card-foreground"
        >
          {state.message}
        </p>
      ) : null}

      {state.status === "error" && !state.fieldErrors ? (
        <p
          id="contact-form-error"
          role="alert"
          className="rounded-md border border-destructive/30 bg-destructive/10 p-4 text-sm text-destructive"
        >
          {state.message}
        </p>
      ) : null}

      <div className="grid gap-6 sm:grid-cols-2">
        <Field
          id="contact-name"
          name="name"
          label="Name"
          autoComplete="name"
          maxLength={200}
          required
          error={nameError}
        />
        <Field
          id="contact-email"
          name="email"
          label="Email"
          type="email"
          autoComplete="email"
          maxLength={320}
          required
          error={emailError}
        />
      </div>

      <Field
        id="contact-subject"
        name="subject"
        label="Subject"
        maxLength={200}
        required
        error={subjectError}
      />

      <TextareaField
        id="contact-message"
        name="message"
        label="Message"
        rows={6}
        maxLength={5000}
        required
        error={messageError}
      />

      <SubmitButton />
    </form>
  );
}

type FieldProps = {
  id: string;
  name: string;
  label: string;
  type?: string;
  autoComplete?: string;
  maxLength?: number;
  required?: boolean;
  error?: string;
};

function Field({
  id,
  name,
  label,
  type = "text",
  autoComplete,
  maxLength,
  required,
  error,
}: FieldProps) {
  const errorId = `${id}-error`;
  return (
    <div className="space-y-2">
      <label htmlFor={id} className="block text-sm font-medium">
        {label}
        {required ? (
          <span aria-hidden="true" className="ml-0.5 text-destructive">
            *
          </span>
        ) : null}
      </label>
      <input
        id={id}
        name={name}
        type={type}
        autoComplete={autoComplete}
        maxLength={maxLength}
        required={required}
        aria-invalid={error ? true : undefined}
        aria-describedby={error ? errorId : undefined}
        className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
      />
      {error ? (
        <p id={errorId} role="alert" className="text-sm text-destructive">
          {error}
        </p>
      ) : null}
    </div>
  );
}

type TextareaFieldProps = Omit<FieldProps, "type" | "autoComplete"> & {
  rows: number;
};

function TextareaField({
  id,
  name,
  label,
  rows,
  maxLength,
  required,
  error,
}: TextareaFieldProps) {
  const errorId = `${id}-error`;
  return (
    <div className="space-y-2">
      <label htmlFor={id} className="block text-sm font-medium">
        {label}
        {required ? (
          <span aria-hidden="true" className="ml-0.5 text-destructive">
            *
          </span>
        ) : null}
      </label>
      <textarea
        id={id}
        name={name}
        rows={rows}
        maxLength={maxLength}
        required={required}
        aria-invalid={error ? true : undefined}
        aria-describedby={error ? errorId : undefined}
        className="flex min-h-[120px] w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
      />
      {error ? (
        <p id={errorId} role="alert" className="text-sm text-destructive">
          {error}
        </p>
      ) : null}
    </div>
  );
}
