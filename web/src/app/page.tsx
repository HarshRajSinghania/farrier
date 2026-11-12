import type { Metadata } from "next";
import { DeviceStrip, Deploy, Faq, Features, Hero, How, Integrations, Lifetimes, Security } from "@/components/landing/sections";
import { SiteFooter } from "@/components/site/footer";
import { SiteHeader } from "@/components/site/header";

export const metadata: Metadata = {
  title: "Farrier: certificate renewal for firewalls, load balancers and appliances",
  description:
    "Open-source, self-hosted certificate renewal for F5, FortiGate, Palo Alto and Java keystores, with change packs for every other device.",
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
