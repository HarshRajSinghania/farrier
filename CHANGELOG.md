# Changelog

All notable changes to Farrier are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html):

- **MAJOR** for changes that break the REST API, the CLI, config files or stored data.
- **MINOR** for new features that keep existing setups working.
- **PATCH** for fixes.

Until 1.0.0, minor releases may still change the API; each one says how to upgrade.

To release: bump `farrier/__init__.py` and `web/package.json` to the same version, move the
Unreleased notes under a new heading, then push the tag `vX.Y.Z`. The release workflow refuses
a tag that doesn't match both versions and this file.

## [Unreleased]

### Added

- Let's Encrypt: renewal timing from the CA (ARI, RFC 9773) and `replaces` on new orders,
  certificate profiles (`classic`, `tlsserver`, `shortlived`), preferred alternate chains,
  and rate-limit handling with `Retry-After`.
- CI runs the ACME client against Pebble, Let's Encrypt's ACME test server.
- Dashboard Settings: edit the renewal policy; view CAs, DNS accounts, notifiers and the engine.
- `GET /api/config` and `PUT /api/config/settings`.

### Changed

- The private CA adds key identifiers (AKI, SKI) to the certificates it issues.

## [0.1.0] - 2026-11-12

First public release.

### Added

- Renewal engine: scan, plan inside change windows with daily caps, issue, deploy, verify, roll back.
- Connectors for F5 BIG-IP, FortiGate, Palo Alto PAN-OS, Java keystores and files over SSH, plus
  change packs (PEM, PFX, runbook, ticket) for every other device.
- ACME client (RFC 8555) with External Account Binding, presets for Let's Encrypt, ZeroSSL,
  Google Trust Services, Buypass, SSL.com, DigiCert and Sectigo, and a built-in private CA.
- DNS-01 through 29 DNS providers with several accounts each and CNAME delegation.
- SQLite, PostgreSQL and MySQL, schema migrations, and several replicas with leader election.
- Deployment verification (fingerprint, chain, names, every VIP), domain health grades and a
  zombie certificate scanner.
- MCP server for Claude, Gemini CLI, Codex and other MCP clients, read-only by default.
- Web dashboard with OIDC single sign-on and viewer, operator and admin roles; docs and site.
- Prometheus metrics, CSV inventory, and Slack, Teams, webhook and email (SMTP, SES) alerts.

[Unreleased]: https://github.com/gagankarthik/farrier/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/gagankarthik/farrier/releases/tag/v0.1.0
