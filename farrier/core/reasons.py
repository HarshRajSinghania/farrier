"""Machine-readable reasons a renewal is stuck or failed, with one line on what to do.

Codes are derived in one place, here, from what the engine already records: the renewal's state, its
error text and its approval record. Nothing extra is stored, so rows written by older versions get a
code too. The API (GET /api/renewals, /api/endpoints/{id}/explain), the CLI (farrier explain), the
dashboard and /metrics (farrier_renewal_failures_total) all read this mapping.
"""
from __future__ import annotations

HINTS = {
    "ISSUE_RATE_LIMITED": "The CA is rate limiting this account or name; Farrier waits for its Retry-After. "
                          "Stop forced renewals and check for duplicate certificates.",
    "ISSUE_DNS": "The DNS-01 challenge failed: check the DNS account's credentials and zone, and that the "
                 "_acme-challenge TXT record is visible from public resolvers.",
    "NOT_PREVALIDATED": "The CA authorizes names out of band and this name is not prevalidated: add the domain "
                        "(AWS ACM: farrier acm domain add) and renew.",
    "ISSUE_CA_ERROR": "The CA refused or failed the request: read the error, check the issuer's credentials "
                      "(EAB, API key, CA status) and renew.",
    "POLICY_DENIED": 'The issuance policy (settings.json "policy") forbids these names, this issuer or this key '
                     "type: fix the endpoint or the policy, then renew.",
    "APPROVAL_PENDING": "Waiting for approval: approve in Renewals (POST /api/renewals/{id}/approve) or in the "
                        "ServiceNow change.",
    "APPROVAL_OVERDUE": "Still unapproved and past the safety deadline: the current certificate expires soon. "
                        "Approve now.",
    "APPROVAL_REJECTED": "Rejected by an approver: the next tick plans a new renewal that waits for approval again; "
                         "resolve the objection (or change the endpoint) first.",
    "DEPLOY_FAILED": "The connector could not install the certificate: check the device's address, credentials "
                     "and API access, then renew.",
    "DEPLOY_RUNNER_OFFLINE": "No runner of the endpoint's group answered: start `farrier runner` in that segment "
                             "and check its token and outbound HTTPS.",
    "VERIFY_MISMATCH": "The endpoint never served the new certificate: check the right virtual server/profile was "
                       "changed, every node behind the name, and caches or CDNs in front.",
    "VERIFY_CHAIN": "The new certificate is live but its chain is incomplete or untrusted, or it does not cover "
                    "every name: install the intermediates and check the endpoint's SANs.",
    "ROLLBACK_FAILED": "The deploy did not go live and the rollback did not finish: check the device by hand, "
                       "it may serve a half-applied change.",
    "OVERDUE_MANUAL": "The manual change was not installed before the deadline: install the change pack now; the "
                      "current certificate expires soon.",
    "SUPERSEDED": "Someone installed a different certificate; nothing to do unless that was a mistake.",
    "UNKNOWN": "Read the error and the endpoint's activity log; `farrier explain <endpoint>` shows the plan.",
}
CODES = tuple(HINTS)
FAILED_STATES = ("failed", "rolled_back")


def code(state: str | None, error: str | None, approval: dict | None = None) -> str | None:
    """The reason code for a renewal row (None when nothing is wrong or waiting)."""
    if approval:
        if approval.get("state") == "pending" and state == "planned":
            return "APPROVAL_OVERDUE" if approval.get("overdue") else "APPROVAL_PENDING"
        if approval.get("state") == "rejected":
            return "APPROVAL_REJECTED"
    if not error:
        return None
    e = error.lower()
    if e.startswith("policy:"):
        return "POLICY_DENIED"
    if e.startswith("overdue"):
        return "OVERDUE_MANUAL"
    if "rollback failed" in e or "rollback did not finish" in e:
        return "ROLLBACK_FAILED"
    if "no runner of" in e or "stopped answering" in e or "(no answer)" in e:
        return "DEPLOY_RUNNER_OFFLINE"
    if e.startswith("deploy failed"):
        return "DEPLOY_FAILED"
    if "chain:" in e or "hostname:" in e:
        return "VERIFY_CHAIN"
    if e.startswith("verify:") or "never went live" in e:
        return "VERIFY_MISMATCH"
    if e.startswith("a different cert"):
        return "SUPERSEDED"
    if state in ("planned", *FAILED_STATES) and (e.startswith("issuance") or state == "planned"):
        if "not prevalidated" in e:
            return "NOT_PREVALIDATED"
        if any(s in e for s in ("ratelimited", "rate limit", "too many", "acme 429")):
            return "ISSUE_RATE_LIMITED"
        if any(s in e for s in ("dns", "txt record", "nxdomain", "servfail", "zone")):
            return "ISSUE_DNS"
        return "ISSUE_CA_ERROR"
    return "UNKNOWN"


def annotate(row: dict, approval: dict | None = None) -> dict:
    """Add reason_code and hint to a renewal row (both None when there is nothing to explain)."""
    c = code(row.get("state"), row.get("error"), approval)
    row["reason_code"], row["hint"] = c, HINTS.get(c)
    return row
