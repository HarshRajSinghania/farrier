/** Single source for names and links. Forks change these and nothing else. */
import pkg from "../../package.json";

export const site = {
  name: "Farrier",
  tagline: "Agentless machine identity automation",
  description:
    "Farrier discovers, manages and secures every machine identity across your infrastructure: TLS certificates, SSH keys, cryptographic assets and post-quantum readiness. No agents. No manual renewals. No missed expirations.",
  url: process.env.NEXT_PUBLIC_SITE_URL || "http://localhost:3000", // ||, not ??: an empty value must not win
  github: "https://github.com/gagankarthik/farrier",
  license: "MIT",
  version: pkg.version, // bumped with farrier/__init__.py; the release workflow checks they match
};
