/** Single source for names and links. Forks change these and nothing else. */
import pkg from "../../package.json";

export const site = {
  name: "Farrier",
  tagline: "Certificate renewal for the machines ACME can't reach",
  description:
    "Open-source certificate automation for load balancers, firewalls, VPNs, Java keystores and vendor appliances. Get ready for 47-day TLS certificates.",
  url: process.env.NEXT_PUBLIC_SITE_URL ?? "http://localhost:3000",
  github: "https://github.com/gagankarthik/farrier",
  license: "MIT",
  version: pkg.version, // bumped with farrier/__init__.py; the release workflow checks they match
};
