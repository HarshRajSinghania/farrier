"use client";

import { useSearchParams } from "next/navigation";
import { CircleAlert, CircleCheck, LogIn } from "lucide-react";
import { Button } from "@/components/ui/button";
import { safeReturnTo } from "@/lib/auth/csrf";
import { cn } from "@/lib/utils";

const MESSAGES: Record<string, { tone: "error" | "info"; text: string }> = {
  expired: { tone: "info", text: "Your session ended. Sign in again to continue." },
  signed_out: { tone: "info", text: "You have signed out." },
  stale: { tone: "error", text: "That sign-in link expired or was already used. Start again." },
  denied: { tone: "error", text: "The sign-in was cancelled or refused by your identity provider." },
  forbidden: {
    tone: "error",
    text: "Your account isn't in a group that may use this dashboard. Ask your administrator for access.",
  },
  provider: { tone: "error", text: "We couldn't complete the sign-in with your identity provider. Try again shortly." },
  misconfigured: { tone: "error", text: "Single sign-on isn't set up correctly on this server. Check its logs." },
};

export function SignInPanel() {
  const q = useSearchParams();
  const returnTo = safeReturnTo(q.get("returnTo"));
  const code = q.get("signed_out") ? "signed_out" : q.get("error");
  const msg = code ? (MESSAGES[code] ?? MESSAGES.provider) : null;
  const Icon = msg?.tone === "info" ? CircleCheck : CircleAlert;

  return (
    <>
      {msg && (
        <p
          role={msg.tone === "error" ? "alert" : "status"}
          className={cn(
            "mt-6 flex items-start gap-2 rounded-md px-4 py-2 text-sm",
            msg.tone === "error" ? "bg-critical/10 text-critical-fg" : "bg-muted text-foreground",
          )}
        >
          <Icon className="mt-1 size-4 shrink-0" aria-hidden />
          {msg.text}
        </p>
      )}
      <Button asChild size="lg" className="mt-6 w-full">
        {/* a full navigation: the browser goes to the identity provider and back */}
        <a href={`/auth/login?returnTo=${encodeURIComponent(returnTo)}`}>
          <LogIn /> Continue with single sign-on
        </a>
      </Button>
    </>
  );
}
