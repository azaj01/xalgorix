import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

/**
 * `cn` — conditional className helper used by every shadcn/ui component.
 * Re-exported so apps can `import { cn } from "@xalgorix/ui/lib/cn"`.
 */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}
