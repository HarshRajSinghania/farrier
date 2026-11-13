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
import { FAQ } from "@/components/landing/sections";
import { JsonLd } from "@/components/site/json-ld";
import { site } from "@/lib/site";
import { SiteFooter } from "@/components/site/footer";
import { SiteHeader } from "@/components/site/header";
import { LandingMotion } from "@/components/landing/motion";

export const metadata: Metadata = {
  title: "Farrier: agentless machine identity automation",
  description:
    "Discover, manage and secure TLS certificates, SSH keys and cryptographic assets, and track post-quantum readiness. Open source, self-hosted, no agents.",
  alternates: { canonical: "/" },
};

export default function Home() {
  return (
    <div data-landing className="flex min-h-full flex-col bg-background">
      <JsonLd
        data={[
          {
            "@context": "https://schema.org",
            "@type": "SoftwareApplication",
            name: site.name,
            description: site.description,
            url: `${site.url}/`,
            applicationCategory: "SecurityApplication",
            operatingSystem: "Linux, Docker, Kubernetes",
            softwareVersion: site.version,
            license: "https://opensource.org/licenses/MIT",
            offers: { "@type": "Offer", price: "0", priceCurrency: "USD" },
            codeRepository: site.github,
          },
          {
            "@context": "https://schema.org",
            "@type": "FAQPage",
            mainEntity: FAQ.map(([q, a]) => ({ "@type": "Question", name: q, acceptedAnswer: { "@type": "Answer", text: a } })),
          },
        ]}
      />
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
