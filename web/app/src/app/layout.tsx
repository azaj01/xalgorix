import "@xalgorix/ui/globals.css";

import type { Metadata } from "next";
import type { ReactNode } from "react";

export const metadata: Metadata = {
  title: {
    default: "Xalgorix Dashboard",
    template: "%s · Xalgorix",
  },
  robots: { index: false, follow: false },
  metadataBase: new URL(
    process.env.NEXT_PUBLIC_APP_URL ?? "https://app.xalgorix.com",
  ),
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" className="dark" suppressHydrationWarning>
      <body className="min-h-screen bg-background text-foreground antialiased">
        {children}
      </body>
    </html>
  );
}
