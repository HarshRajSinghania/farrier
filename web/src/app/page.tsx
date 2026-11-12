import type { Metadata } from "next";
import { DeviceStrip, Deploy, Faq, Features, Hero, How, Integrations, Lifetimes, Security } from "@/components/landing/sections";
import { SiteFooter } from "@/components/site/footer";
import { SiteHeader } from "@/components/site/header";

export const metadata: Metadata = {
  title: "Farrier: agentless machine identity automation",
  description:
    "Discover, manage and secure TLS certificates, SSH keys and cryptographic assets, and track post-quantum readiness. Open source, self-hosted, no agents.",
};

export default function Home() {
  return (
    <>
      <SiteHeader overlay />
      <main id="top">
        <Hero />
        <DeviceStrip />
        <How />
        <Features />
        <Integrations />
        <Lifetimes />
        <Deploy />
        <Security />
        <Faq />
      </main>
      <SiteFooter />
    </>
  );
}
