# Security policy

Farrier holds private keys and talks to the management interfaces of firewalls and load balancers,
so security reports get priority over everything else.

## Reporting a vulnerability

**Please don't open a public issue.** Report privately through GitHub:
[Report a vulnerability](https://github.com/gagankarthik/farrier/security/advisories/new).

Include what you can of:

- the affected version or commit, and how Farrier was deployed;
- steps to reproduce, or a proof of concept;
- the impact as you understand it.

## What to expect

| Step | Within |
|---|---|
| Acknowledgement | 3 working days |
| First assessment and severity | 7 days |
| Fix or mitigation for critical and high issues | 30 days |

We'll keep you updated, agree a disclosure date with you, and credit you in the advisory and the
changelog unless you'd rather stay anonymous.

## Supported versions

Farrier is pre-1.0. Security fixes go into the latest minor release only.

| Version | Supported |
|---|---|
| 0.1.x | Yes |

## Scope

In scope: the engine (`farrier/`), the web app and dashboard (`web/`), the container images and
the Kubernetes manifests in this repository. Examples are key exposure, authentication or
authorization bypass, secrets leaking through the API, logs or MCP, request forgery against devices
or arbitrary hosts, and code execution.

Out of scope: vulnerabilities in a CA, DNS provider or appliance itself, and findings that need an
already-compromised host or admin token.

## Hardening

See the [security model and hosting checklist](web/src/app/docs/security/page.mdx).
