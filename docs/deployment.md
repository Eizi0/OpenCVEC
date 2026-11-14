# Deploying OpenCVEC on a small budget

OpenCVEC fits in a single container plus PostgreSQL. At idle, it uses about 11 MiB of RAM and PostgreSQL about 40 MiB. A **1 vCPU / 1 GB** VM, a mini PC or a **Raspberry Pi 4** (arm64 image) is enough.

There are two deployment modes, depending on what you want to test.

| | Internal network | External (Internet) |
|---|---|---|
| What gets tested | internal servers, workstations, business applications | exposed services: VPN, websites, mail |
| Where to install | an internal VM | a small VPS |
| Canary zone | internal name (e.g. `canary.opencvec.intra`) | delegated public subdomain (e.g. `c.opencvec.example.com`) |
| How targets reach the receiver | conditional forwarder on the internal DNS | public NS delegation |
| Proof of ownership | allowlisted internal ranges | DNS TXT or /.well-known |

Nothing prevents running both: one internal instance and one external instance.

## Internal mode

1. **Install** OpenCVEC on an internal VM (for example 10.0.5.20):
   ```sh
   cp .env.example .env
   # OPENCVEC_CANARY_ZONE=canary.opencvec.intra
   # OPENCVEC_CANARY_IP=10.0.5.20
   # OPENCVEC_PROOF_RESOLVERS=10.0.0.53     (your internal DNS, for the self-test)
   docker compose up -d
   ```
2. **Forward the canary zone to OpenCVEC** on the internal DNS, so that every machine using it can "call" the canary.
   - Active Directory / Windows DNS:
     ```powershell
     Add-DnsServerConditionalForwarderZone -Name "canary.opencvec.intra" -MasterServers 10.0.5.20 -ReplicationScope Forest
     ```
   - Unbound (pfSense, OPNsense):
     ```
     forward-zone:
       name: "canary.opencvec.intra"
       forward-addr: 10.0.5.20
     ```
   - BIND: `zone "canary.opencvec.intra" { type forward; forward only; forwarders { 10.0.5.20; }; };`
   - dnsmasq / AdGuard Home / Pi-hole: `server=/canary.opencvec.intra/10.0.5.20`
3. **Allowlist internal ranges**: Administration › Allowlist (for example `10.0.0.0/16`, with a reason).
4. **Check**: Administration › Canary receiver › Run self-test. The line "Delegation via 10.0.0.53" must succeed.

An "inconclusive" check on the internal network often means that a server does not use the internal DNS, or that its outbound traffic is filtered. That is useful information in itself.

## External mode

1. A VPS with a public IP, with ports **53/udp, 53/tcp and 80** open.
2. At the domain registrar:
   ```
   c.opencvec.example.com.    NS   ns1.opencvec.example.com.
   ns1.opencvec.example.com.  A    <public IP>
   ```
3. In `.env`: `OPENCVEC_CANARY_ZONE=c.opencvec.example.com`, `OPENCVEC_CANARY_IP=<public IP>`, `OPENCVEC_NS_NAME=ns1.opencvec.example.com`.
4. Put the interface (port 8080) behind an HTTPS proxy (Caddy, Traefik, nginx), with `OPENCVEC_TRUST_PROXY=true` and `OPENCVEC_SECURE_COOKIES=true`. Do not expose the interface without filtering: restrict it with a VPN or by source address.
5. Prove asset ownership with DNS TXT or /.well-known, then run the self-test.

## Architectures

The image is cross-compiled for amd64 and arm64, without emulation:
```sh
docker buildx build --platform linux/amd64,linux/arm64 -t opencvec:latest .
```

## Backup

What to back up:
- the PostgreSQL database (`docker compose exec db pg_dump -U opencvec opencvec > backup.sql`);
- the value of `OPENCVEC_SECRET_KEY`. Without it, TOTP secrets and the canary HMAC key become unreadable, and the instance no longer starts.
