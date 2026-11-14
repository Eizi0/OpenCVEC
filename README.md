<h1 align="center">OpenCVEC</h1>
<p align="center"><strong>CVE Checker</strong>: self-hosted, canary-based vulnerability verification.</p>

OpenCVEC lets an organization **prove that a CVE affects its own assets** without exploiting anything else. Each check sends a fixed payload whose only possible effect is to make the target resolve a unique DNS name, the **canary**, or read a **canary file** planted on the asset. When the built-in receiver sees that request, the vulnerability is proven, with a timestamped, signed trace.

The tool is designed so that it cannot be turned against a third party:
- no check runs without proof that the asset belongs to the organization;
- no payload or callback URL can be edited;
- outbound connections stay confined to the proven scope.

It targets small-budget teams. It ships as a single 7 MB container that uses about 11 MiB of RAM at idle, plus PostgreSQL, and runs either inside the internal network or on a small VPS (see [docs/deployment.md](docs/deployment.md)). New CVEs are added through **signed plugins**, with no application update.

> The web interface and code comments are currently in French; the documentation is in English.

## How it works

1. **Declare an asset** (domain name, IP or range) and **prove ownership**, in one of three ways:
   - a DNS record `TXT _opencvec.<host>`, which a majority of the queried resolvers must see;
   - a file `/.well-known/opencvec-<id>.txt` served by the host;
   - for internal networks, a range allowlisted by an administrator, with a mandatory reason and a review at least every 90 days.

   Proof lasts 30 days and is **re-validated before every campaign**.
2. **Launch a check.** OpenCVEC issues a canary `<point>.<token>.<zone>`, where the token is `nonce ‖ HMAC(key, asset ‖ check ‖ nonce)`. It is single-use and expires after 15 minutes.
3. **Receive the callback.** The built-in authoritative DNS server (plus an HTTP receiver) records the request. The first valid callback gives a **proven** verdict, with the source IP, request type, injection point and delay. Without a callback within the configured time, the verdict is **inconclusive**.

Requests received outside a check are logged as rejected and never produce a verdict. This covers unknown or forged tokens, expired canaries and replays after a verdict.

### Canary file

For flaws that give file access or code execution, the organization plants a **canary file** on the asset. Its content is a unique token, generated from the asset page together with the Linux or Windows command to deploy it. The check exploits the flaw only to **read that file back**. The token either comes back in the response or is exfiltrated to the DNS receiver, so the proof is obtained without touching anything else.

The canary also works as a **honeytoken**: if it is read outside a check, OpenCVEC raises a compromise alert (dashboard, callback log, audit log).

## Plugins

A plugin is a **signed** YAML file (Ed25519) that describes a check:
- the steps: HTTP requests or TCP/TLS exchanges;
- the extractions and version rules;
- the proof mode.

Plugins are installed from **Plugins › Official catalog**, by URL or by file. Before installing, the administrator sees the full content, the steps and the signature check result.

- **The engine enforces scope.** A step gives a path or a port, never a host. Variables are limited to the target and the canaries, and unknown fields are rejected. Response bodies are never stored.
- **Only trusted publishers are accepted.** The official publisher is built in, and teams can add their own key. Unsigned plugins require **developer mode**, which is audited. Signatures are re-verified at every load, so removing a publisher immediately unloads its plugins.
- **Write, sign and publish** with `opencvec plugin keygen | lint | sign | verify | index`. See [docs/plugins.md](docs/plugins.md).

Every checker is a plugin. The 10 official plugins are **embedded in the binary and preinstalled at first start**, including on instances without Internet access. They are verified against the official key and updated automatically when a newer version ships, and an administrator can uninstall any of them.

| Official plugin | CVE | Proof | Lab validation |
|---|---|---|---|
| Log4JChecker | CVE-2021-44228, CVE-2021-45046 | DNS callback (JNDI lookup, 12 injection points) | proven on Solr 8.11.0, inconclusive on 8.11.2 |
| Text4ShellChecker | CVE-2022-42889 | DNS callback (`${dns:}`) | proven with commons-text 1.9, inconclusive with 1.10.0 |
| SpringFunctionChecker | CVE-2022-22963 | DNS callback (SpEL) | proven on Spring Cloud Function 3.2.2 |
| ApacheTraversalChecker | CVE-2021-41773 | canary file read back | proven on httpd 2.4.49 (vulnerable configuration), inconclusive on 2.4.51 |
| ConfluenceChecker | CVE-2022-26134 | DNS callback (OGNL limited to `InetAddress.getByName`) | not validated (license required) |
| PHPCGIChecker | CVE-2024-4577 | DNS callback (`gethostbyname` through PHP-CGI) | not validated (Windows target required) |
| RegreSSHionChecker | CVE-2024-6387 | SSH banner (TCP) | probable on OpenSSH 9.6, patched on 9.9 |
| PHP2ShellChecker | CVE-2026-109618, CVE-2026-109619 | version fingerprint | probable on PHP 8.3.20 |
| WP2ShellChecker | CVE-2026-63030, CVE-2026-60137 | version fingerprint (generator tag, then RSS feed) | probable on WordPress 6.9.4, patched on 7.0.2 |
| FortiBleedChecker | "FortiBleed" campaign (related CVEs) | FortiGate interface exposure | unit tests only |

**Fingerprint-only plugins.** PHP2Shell and WP2Shell are actively exploited code execution chains, and RegreSSHion is a race condition. Proving them with a canary would require a real exploit, so OpenCVEC only reads the exposed version, and the best possible verdict is "probable".

**FortiBleed** is a credential-theft campaign, not a CVE. Its plugin reports a reachable FortiGate admin interface or SSL-VPN portal ("exposed").

Possible verdicts: proven, probable, exposed, patched version, inconclusive, error.

## Safeguards

- **Proof of ownership**, required and re-validated at launch. Removing a range from the allowlist invalidates the proofs that depend on it.
- **Fixed payloads.** The API rejects unknown fields, so no custom payload or callback URL can be added.
- **Network guard.** The IP actually contacted is checked at connection time. Private, loopback and cloud metadata addresses are refused unless allowlisted, and redirects are not followed. This blocks DNS rebinding and pivoting.
- **Rate limits** per asset (per day) and per user (per hour).
- **Roles** (administrator, analyst, viewer) and TOTP two-factor authentication, which can be enforced for all users.
- **Append-only audit log.** A PostgreSQL trigger forbids UPDATE and DELETE, and the SHA-256 hash chain can be verified from the interface. Every refusal is logged.
- **Signed plugins**: trusted publishers, review before installation, signature re-checked at every load, no response data kept.
- **Reports**: printable HTML (PDF through the browser) or JSON, with the SHA-256 fingerprint kept by the instance.

## Installation

The full guide is in [docs/deployment.md](docs/deployment.md). It covers two modes:
- **internal**: a conditional DNS forwarder, no public domain needed;
- **external**: NS delegation.

Quick start in external mode requires Docker, a domain whose subzone you can delegate, and ports 53 (UDP and TCP) and 80 reachable from the Internet.

```sh
cp .env.example .env    # then fill in the values
docker compose up -d
```

Delegate the canary zone to the server at your registrar:

```
c.opencvec.example.com.    NS   ns1.opencvec.example.com.
ns1.opencvec.example.com.  A    <server public IP>
```

Then **Administration › Canary receiver › Run self-test** checks local listening and public delegation.

The first administrator is created at startup. If `OPENCVEC_ADMIN_PASSWORD` is empty, a random password is printed once in the logs. `opencvec reset-admin <email>` resets an account.

Put the interface (port 8080) behind an HTTPS reverse proxy, with `OPENCVEC_TRUST_PROXY=true` and `OPENCVEC_SECURE_COOKIES=true`.

### Environment variables

| Variable | Purpose | Default |
|---|---|---|
| `OPENCVEC_DATABASE_URL` | PostgreSQL connection | required |
| `OPENCVEC_SECRET_KEY` | AES-256 key for secrets at rest (`openssl rand -base64 32`) | empty = secrets in clear text |
| `OPENCVEC_CANARY_ZONE` | DNS zone delegated to the receiver | `c.opencvec.local` |
| `OPENCVEC_CANARY_IP` | IP returned for names in the zone | `127.0.0.1` |
| `OPENCVEC_NS_NAME` | announced name server | `ns1.<zone>` |
| `OPENCVEC_DNS_ADDR` / `OPENCVEC_CANARY_HTTP_ADDR` | receiver DNS / HTTP listeners (`off` to disable) | `:5353` / `:8081` |
| `OPENCVEC_PROOF_RESOLVERS` | resolvers for TXT proofs and the self-test | `1.1.1.1,8.8.8.8,9.9.9.9` |
| `OPENCVEC_PLUGIN_REGISTRY` | official plugin repository (folder containing `index.json`) | `plugins/` folder of this repository |
| `OPENCVEC_ADMIN_EMAIL` / `OPENCVEC_ADMIN_PASSWORD` | first administrator | `admin@opencvec.local` |
| `OPENCVEC_REQUIRE_MFA` | enforce two-factor authentication | `false` |
| `OPENCVEC_TRUST_PROXY`, `OPENCVEC_SECURE_COOKIES` | deployment behind HTTPS | `false` |

Durations (canary lifetime, callback wait), rate limits and developer mode are set in Administration.

## Validation lab

`lab/compose.yaml` starts OpenCVEC on an isolated network, with vulnerable targets and their patched versions. Targets resolve names through the receiver, so no canary traffic leaves the lab.

```sh
docker compose -f lab/compose.yaml up -d --build
./scripts/lab-e2e.sh            # Log4Shell, Text4Shell, PHP2Shell: 5 scenarios
./scripts/lab-plugins-e2e.sh    # Apache, Spring, RegreSSHion, WP2Shell: 7 scenarios, tampered plugin rejected, honeytoken alert
```

The lab interface is served at http://127.0.0.1:8095 (test credentials in `lab/compose.yaml`).

## Development

```sh
docker run -d --name opencvec-testdb -e POSTGRES_USER=opencvec -e POSTGRES_PASSWORD=opencvec -e POSTGRES_DB=opencvec -p 55432:5432 postgres:17-alpine
export OPENCVEC_TEST_DATABASE_URL="postgres://opencvec:opencvec@127.0.0.1:55432/opencvec?sslmode=disable"
go test ./...                    # unit and integration tests (end-to-end proof over real DNS)
cd web && npm ci && npm test && npm run build
```

Stack: Go (API, `miekg/dns` receiver, runner, YAML plugin engine), PostgreSQL, React and Vite (embedded in the binary), distroless non-root image for amd64 and arm64.

## Limitations

A canary proof is only possible if the flaw lets the attacker:
- get data evaluated;
- trigger an outbound connection;
- or read the canary file.

What a canary cannot prove:
- memory leaks, authentication bypasses, client-side flaws and local privilege escalation;
- memory corruption bugs, which would require a real exploit, so they stay fingerprint-only.

"Inconclusive" does not mean "not vulnerable". It can come from:
- DNS or HTTP egress filtering;
- a WAF;
- an injection point not covered by the check;
- delayed triggering (logs processed later).

A device that resolves names seen in traffic (sandbox, EDR, mail gateway) can also trigger a canary instead of the application. The injection point and the delay help tell them apart.

## Responsible use

Only use OpenCVEC on systems your organization owns or is explicitly authorized to test. See [SECURITY.md](SECURITY.md).

## License

MIT
