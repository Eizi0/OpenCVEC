# Writing, signing and publishing a plugin

A plugin adds a check to OpenCVEC without updating the application. Example: a new CVE comes out, the OpenCVEC team publishes `new-cve.yaml` and its signature on GitHub, and every organization installs it from **Plugins › Official catalog**.

## Rules enforced by the engine

- **A plugin does not choose its target.** An HTTP step gives a *path* (`/x/y`), a TCP step gives a *port*. The host is always the asset of the check, whose ownership has been proven, and the network guard checks the IP being contacted.
- **Proof goes through a canary.** There are two families of proof:
  - in `canary` mode, the target resolves `{{canary.dns.pN}}` or calls `{{canary.url.pN}}`, or the content of the canary file comes back in a response or through DNS exfiltration;
  - in `fingerprint` mode, no payload is sent: only the fingerprint (version, banner) is compared with patched versions.
- **Nothing from responses is stored**, only the extracted values and whether the token was found.
- **Unknown fields are rejected**, variables are limited to the list below, and the maximum size is 256 KiB.

The full plugin content is shown to the administrator before installation.

## Canary file

For flaws that give access to the file system or to code execution, the organization plants a **canary file** on the asset from the asset page. Its content is a unique token unknown to the outside. The plugin exploits the flaw *only* to read this file:

- `proofs.file_in_response: true`: the token appears in a response (file read, code execution with visible output);
- `proofs.file_callback: true`: the target exfiltrates the token through DNS, for example `getent hosts $(cat {{canary.file.path}}).<zone>`, for "blind" code execution.

The same file also works as a **honeytoken**: if it is read outside a check, OpenCVEC raises a compromise alert.

## Format

```yaml
id: example-cve-2099-0001        # lowercase, digits, hyphens (3 to 63)
name: ExampleChecker
version: 1.0.0                   # x.y.z; increment on every release
author: Your team
cves: [CVE-2099-0001]
product: Product X 1.0 to 1.4
description: What the plugin checks and under which conditions the flaw is exploitable.
mode: canary                     # canary or fingerprint
proof: DNS request to the canary
sent: Honest description of what is sent to the target (shown before installation and in reports).
remediation: [Upgrade to 1.5, …]
references: [https://…]
tags: [productx]                 # used for suggestions based on asset tags
default_port: 8443               # port of TCP steps (otherwise the target URL port)

steps:
  - id: injection
    http:
      method: POST               # GET by default
      path: "/api/import?url={{canary.url.p1}}"
      headers:
        X-Custom: "{{canary.dns.p2}}"   # case preserved as written
      body: "…"
    points:                      # optional labels, shown in the verdict ("triggered through X-Custom")
      p1: query parameter url
      p2: header X-Custom
  - id: banner
    when: {missing: version}     # optional: run only if an earlier step did not find the value
    tcp:
      port: 22                   # optional
      tls: false
      send: "HELLO\r\n"          # or send_hex: "16 03 01 …"
      read_bytes: 256
      timeout: 5s

proofs:                          # canary mode only
  callback: true
  file_in_response: false
  file_callback: false
```

In `fingerprint` mode, extractions feed a version rule or matchers:

```yaml
extract:
  - name: version
    step: banner
    part: body                   # body, status, all, header:<Name>
    regex: 'ProductX/([0-9]+)\.([0-9]+)\.([0-9]+)'
    format: "{1}.{2}.{3}"
version_rule:
  var: version
  vulnerable:
    - range: ">=1.0, <1.5"
      message: "ProductX {{version}}: vulnerable according to its version."
  patched_message: "ProductX {{version}}: patched version."
  missing_message: "Version not exposed."
matchers:                        # evaluated before version_rule; first match wins
  - step: banner
    status: [200]
    contains: ["productx-admin"]
    also:                        # optional: every extra condition must hold too
      - step: other-step
        status: [200]
    when: {missing: version}     # optional
    verdict: exposed             # probable, exposed, patched, inconclusive
    message: "Admin console exposed."
fallback_message: "Nothing recognized on this URL."   # when no matcher or rule applies
```

A version range can carry its own verdict (`verdict: inconclusive` for an end-of-life branch the advisory does not cover, for instance). The first matching range wins.

Messages shown in the interface are free text. The official plugins are written in French because the interface is in French.

### Variables

| Variable | Value |
|---|---|
| `{{canary.dns.p1}}` … `{{canary.dns.p99}}` | unique DNS name for the injection point |
| `{{canary.url.pN}}` | `http://<point name>/` (HTTP receiver) |
| `{{canary.file.path}}` | path of the canary file planted on the asset |
| `{{target.host}}`, `{{target.port}}`, `{{target.base}}`, `{{target.path}}`, `{{target.url}}` | target URL of the check |
| `{{target.dir}}` | target path without trailing slash (a step path may start with it or with `{{target.path}}`) |
| `{{random}}` | 12 random hexadecimal characters |

Rule and matcher messages can reference extracted values (`{{version}}`).

## Test, sign, publish

```sh
opencvec plugin lint my-plugin.yaml                   # format and safety rules
opencvec plugin keygen ~/.opencvec/keys/my-team        # once: keep the private key secret
opencvec plugin sign ~/.opencvec/keys/my-team.key my-plugin.yaml
opencvec plugin verify ~/.opencvec/keys/my-team.pub my-plugin.yaml
opencvec plugin index plugins/                         # updates the repository index.json
```

To test without signing, an administrator can temporarily enable **developer mode** (Administration › Canary receiver and limits). Turning it on and every unsigned installation are logged.

To publish an internal plugin, add your team's public key in **Plugins › Trusted publishers**, then install the plugin by URL or by file. The official catalog is read from `OPENCVEC_PLUGIN_REGISTRY`, which must contain `index.json`, the `.yaml` files and the `.sig` files.

## Lab validation

Each official plugin must give the expected verdict on a vulnerable target **and** on a patched one. Add targets to `lab/compose.yaml` and cases to `scripts/lab-plugins-e2e.sh`. The current plugins were validated this way on 2026-11-14.

| Plugin | Vulnerable | Patched |
|---|---|---|
| Log4J (CVE-2021-44228) | Solr 8.11.0: proven | Solr 8.11.2: inconclusive |
| Text4Shell (CVE-2022-42889) | commons-text 1.9: proven | commons-text 1.10.0: inconclusive |
| ApacheTraversal (CVE-2021-41773) | httpd 2.4.49 with `Require all granted` on `/`: proven | httpd 2.4.51: inconclusive |
| SpringFunction (CVE-2022-22963) | Spring Cloud Function 3.2.2: proven | no patched image tested |
| RegreSSHion (CVE-2024-6387) | OpenSSH 9.6: probable | OpenSSH 9.9: patched |
| PHP2Shell (CVE-2026-109618/109619) | PHP 8.3.20: probable | version table covered by tests |
| WP2Shell (CVE-2026-63030/60137) | WordPress 6.9.4: probable | WordPress 7.0.2: patched |

Confluence (license), PHP-CGI (Windows target) and FortiBleed (no free FortiGate image) are covered by unit tests only.

The official plugins in `plugins/` are also embedded in the binary (`plugins/embed.go`) and preinstalled at startup, so a release ships with its catalog. A plugin uninstalled by an administrator is not reinstalled.

The lab caught three mistakes that unit tests missed:
- Spring reads a header case-sensitively, while Go canonicalizes header names;
- Alpine prints "OpenSSH_9.6" without the "p1" suffix;
- Apache 2.4.49 is not exploitable in its default configuration.
