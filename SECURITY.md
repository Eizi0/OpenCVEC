# Security

## Reporting a vulnerability

Do not open a public issue. Use the repository's "Report a vulnerability" feature (private security advisory) and include the version, reproduction steps and estimated impact.

## Threat model

OpenCVEC sends requests to systems. The main risk is that it gets misused against a third party. These are the protections in place:

| Targeted abuse | Protection |
|---|---|
| Targeting a system the organization does not own | Mandatory proof of ownership (DNS TXT, /.well-known or administrator allowlist), re-validated for every campaign |
| Running an arbitrary payload | Payloads fixed in code; the API rejects unknown fields; only the canary name is injected |
| DNS rebinding, pivoting to the internal network or cloud metadata | IP checked at connection time; private and reserved addresses refused unless allowlisted; redirects not followed |
| Forging a proof | Canary signed with HMAC for one asset × check pair, single-use and expiring; replays and forged tokens rejected and logged |
| Hiding misuse | Append-only audit log (PostgreSQL trigger) chained with SHA-256 hashes |
| Mass scanning | Rate limits per asset and per user |
| Malicious plugin or compromised repository | Mandatory Ed25519 signature (trusted publishers), re-verified at every load; full content shown before installation; developer mode audited |
| Plugin targeting another host or exfiltrating data | Steps limited to a path or port of the asset; variables limited to the target and canaries; response bodies never stored |
| Real compromise of an asset | The canary file is a honeytoken: read outside a check, it raises an alert |

The WP2Shell and PHP2Shell checkers cover recent, actively exploited code execution flaws. They deliberately contain no exploit and rely on the version fingerprint only.

## Recommended hardening

- Set `OPENCVEC_SECRET_KEY`. Without it, TOTP secrets and the canary HMAC key are stored in clear text.
- Enforce two-factor authentication (`OPENCVEC_REQUIRE_MFA=true`).
- Keep the plugin signing private key out of the repository and off the instance (publisher workstation or vault).
- Serve the interface over HTTPS only, behind a reverse proxy, and avoid exposing it to the Internet. Only the receiver ports (53 and 80) need to be public.
