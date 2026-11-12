"use client";

import { ThemeProvider } from "next-themes";
import { Toaster } from "sonner";
import { Tooltip } from "radix-ui";

export function Providers({ children }: { children: React.ReactNode }) {
  return (
    <ThemeProvider attribute="class" defaultTheme="system" enableSystem disableTransitionOnChange>
      <Tooltip.Provider delayDuration={150}>
        {children}
        <Toaster
          position="bottom-right"
          toastOptions={{
            classNames: {
              toast: "!bg-popover !text-foreground !border-border !shadow-lg",
              description: "!text-muted-foreground",
            },
          }}
        />
      </Tooltip.Provider>
    </ThemeProvider>
  );
}
