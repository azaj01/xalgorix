"use client";

/**
 * Client wrapper around `next-themes`' provider so that `app/layout.tsx`
 * can stay a server component.
 *
 * Implements Requirement 2.6:
 *   "THE Marketing_Site SHALL render a dark theme by default with a
 *    user-selectable light theme persisted in `localStorage` under the
 *    key `xalgorix-theme`."
 */
import { ThemeProvider as NextThemesProvider } from "next-themes";
import type { ThemeProviderProps } from "next-themes/dist/types";
import type { ReactNode } from "react";

export function ThemeProvider({
  children,
  ...props
}: ThemeProviderProps & { children: ReactNode }) {
  return <NextThemesProvider {...props}>{children}</NextThemesProvider>;
}
