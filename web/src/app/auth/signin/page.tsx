import type { Metadata } from "next";
import { Suspense } from "react";
import { Logo } from "@/components/brand";
import { Card, CardContent } from "@/components/ui/card";
import { SignInPanel } from "./signin-panel";

export const metadata: Metadata = {
  title: "Sign in",
  robots: { index: false, follow: false },
};

export default function SignInPage() {
  return (
    <main className="flex flex-1 flex-col items-center justify-center bg-plane px-4 py-16">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex justify-center">
          <Logo className="text-lg" />
        </div>
        <Card>
          <CardContent className="p-6 sm:p-8">
            <h1 className="text-xl font-semibold tracking-tight">Sign in to the dashboard</h1>
            <p className="mt-2 text-[13px] text-muted-foreground">
              Use your organization account. Your access level comes from your groups in the identity provider.
            </p>
            <Suspense fallback={<div className="mt-6 h-11 rounded-md bg-muted" />}>
              <SignInPanel />
            </Suspense>
          </CardContent>
        </Card>
        <p className="mt-6 text-center text-xs text-muted-foreground">
          Trouble signing in? Ask the person who runs Farrier for your organization.
        </p>
      </div>
    </main>
  );
}
