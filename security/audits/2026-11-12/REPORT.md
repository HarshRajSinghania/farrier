# Security audit, 12 November 2026

Scope: the whole repository at `77401a7` (engine `farrier/`, web app and bridge `web/`, `deploy/`, `functions/`,
CI). Method: Cloudflare's security-audit approach: reconnaissance, four independent hunters with a coverage
ledger each, a working local proof for every finding, then fixes with regression tests.

Hunters:
1. Identity, authorization and web.
2. Injection, files and commands.
3. SSRF, secrets and crypto.
4. Logic, deployment and supply chain.

Deviations from the method:
- No OS sandbox: proofs ran in-process (FastAPI TestClient, httpx MockTransport, loopback sockets, WSL `sh`)
  with dummy data.
- Nothing ran against real cloud accounts, appliances or SSH servers.

## Findings

All nine are confirmed with a local proof and fixed, each with a regression test that fails on the old code.

| # | Severity | Finding | Principal | Fix | Test |
|---|---|---|---|---|---|
| 1 | High | Read token could download change packs (private key, PFX passphrase). Found by three hunters independently. | read token | `farrier/api/app.py` `secret_read` | `test_read_token_cannot_download_change_packs` |
| 2 | Critical | Discovery copied names from any served certificate, then an operator could renew and download a key for any names, including wildcards. | operator | discovered endpoints are monitor-only until `POST /api/endpoints/{id}/approve` (admin) | `test_discovered_endpoint_is_monitor_only_until_admin_approves` |
| 3 | Medium | Discovery could overwrite an existing endpoint that shared its generated name. | operator | unique name in `register_scan` | `test_discovery_never_overwrites_an_endpoint_that_shares_its_name` |
| 4 | High | SSH key removal with sudo followed a symlink planted at the predictable backup path: root overwrite and chown on the managed host. | local user on a managed host | `mktemp` backup, no-follow checks, file ops run as the key's owner (`farrier/ssh/collect.py`) | `test_key_removal_write_never_follows_planted_links_and_runs_as_the_account` |
| 5 | High | Secret-ref guard bypassed with `file:/proc/self/environ` and unlisted `FARRIER_*` or cloud env vars, so a stolen admin token could send the master key to its own host. | admin token | always-refused system paths and credential env names (`farrier/security/vault.py`) | `test_secret_refs_never_reach_system_files_or_farrier_and_cloud_credentials` |
| 6 | Medium | Basic-auth lockout keyed on the client-supplied left-most `X-Forwarded-For`, and the whole table was cleared at 10k keys. | unauthenticated | right-most hop, global failure budget, expire-only eviction (`web/src/proxy.ts`) | manual review (proxy imports `next/server`) |
| 7 | Medium | Target expansion materialised the list before the 4096 cap: 152 bytes used 241 MB. | operator | count before building (`farrier/core/discovery.py`) | `test_expand_targets_refuses_before_materialising_huge_ranges` |
| 8 | Medium | A verify rollback ran before its compare-and-set, so a replica could revert a device after another marked the renewal `done`. Also, a pack sweep could delete an `issued` renewal's pack. | operator / replica race | claim `verifying → failed` first; sweep keeps `issued` | `test_verify_rollback_skipped_when_renewal_was_claimed_meanwhile`, `test_sweep_keeps_pack_of_renewal_still_issued` |
| 9 | Medium | A malicious SSH server could stall the probe forever with IGNORE messages, holding the scheduler lock. | any scanned SSH server | per-connection deadline, cap on skipped messages, output caps, lock release | `test_probe_is_bounded_against_a_server_trickling_ignore_messages` |
| 10 | Low | Event Grid identity auth sent Farrier's Azure token to any https endpoint. | admin | identity auth only to `*.eventgrid.azure.net` / `.us` / `.chinacloudapi.cn` | `test_eventgrid_identity_token_only_goes_to_event_grid_hosts` |

## Remaining limits of the fixes

- **#4:** the remote `sudo` must allow switching to the key's owner. Key files owned by root for another
  account now fail with "permission denied" instead of being written as root.
- **#8:** a crash in the middle of a rollback leaves the renewal `failed`, with the event "rolling back".
- **#9:** a single probe can still take about six times the timeout.
- **#5:** with `FARRIER_SECRET_ENV_PREFIX` unset, `env:FARRIER_SECRET_*` stays allowed. That is the documented
  namespace for user secrets.

## Needs validation (depends on your deployment)

- Who can write to the backup bucket. `farrier restore` trusts the backup's rows, including connector
  commands.
- Whether the ingress in front of the dashboard appends or overwrites `X-Forwarded-For`. Appending is
  assumed.
- Whether the Azure web Container App is reachable without Front Door, since `external_enabled = true`.
- Which principals in the AWS account have `events:PutEvents` on the Farrier bus.
- Whether the OIDC provider enforces an exact-match redirect URI when `FARRIER_OIDC_REDIRECT_URI` is unset.
- With an ACME default issuer, whether #2 also yields publicly trusted certificates. It does if a configured DNS
  account covers the requested zone.

## Covered and found sound

- **Engine API:** every `/api` route requires auth; tokens are compared in constant time.
- **Web bridge:** path segments are validated, role rules apply to every route, only safe headers pass through.
- **OIDC:** state, nonce, PKCE, `azp` and asymmetric algorithms only; sealed cookies; CSRF on all writes.
- **MCP:** Origin checks; sessions bound to their token; writes gated.
- **Other:** SQL binding; DNS and TLS parser bounds; no deserialisation sinks; Helm network policies; Terraform
  exposure; CI permissions; git history holds no real secrets.
