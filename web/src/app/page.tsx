import type { Metadata } from "next";
import {
  Deploy,
  Devices,
  Faq,
  Features,
  Hero,
  How,
  Platform,
} from "@/components/landing/sections";
import { SiteFooter } from "@/components/site/footer";
import { SiteHeader } from "@/components/site/header";
import { LandingMotion } from "@/components/landing/motion";

export const metadata: Metadata = {
  title: "Farrier: agentless machine identity automation",
  description:
    "Discover, manage and secure TLS certificates, SSH keys and cryptographic assets, and track post-quantum readiness. Open source, self-hosted, no agents.",
};

export default function Home() {
  return (
    <div data-landing className="flex min-h-full flex-col bg-background">
      <SiteHeader landing />
      <LandingMotion>
        <main id="top">
          <Hero />
          <How />
          <Features />
          <Platform />
          <Devices />
          <Deploy />
          <Faq />
        </main>
        <SiteFooter />
      </LandingMotion>
    </div>
  );
}
