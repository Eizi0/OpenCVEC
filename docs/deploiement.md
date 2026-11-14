# Déployer OpenCVEC à petit budget

OpenCVEC tient dans un seul conteneur, plus PostgreSQL. Au repos, il occupe environ 11 Mio de RAM, et PostgreSQL environ 40 Mio. Une VM de **1 vCPU / 1 Go**, un mini-PC ou un **Raspberry Pi 4** (image arm64) suffisent.

Deux modes de déploiement existent, selon ce que vous voulez tester.

| | Dans le SI (interne) | À l'extérieur (Internet) |
|---|---|---|
| Ce qui est testé | serveurs internes, postes, applications métier | services exposés : VPN, sites, messagerie |
| Où installer | une VM du réseau interne | un petit VPS |
| Zone canari | nom interne (ex. `canary.opencvec.intra`) | sous-domaine public délégué (ex. `c.opencvec.exemple.fr`) |
| Comment les cibles joignent le récepteur | redirecteur conditionnel du DNS interne | délégation NS publique |
| Preuve de propriété | liste blanche des plages internes | DNS TXT ou /.well-known |

Rien n'empêche d'avoir les deux : une instance interne et une instance externe.

## Mode interne (dans le SI)

1. **Installer** OpenCVEC sur une VM interne (par exemple 10.0.5.20) :
   ```sh
   cp .env.example .env
   # OPENCVEC_CANARY_ZONE=canary.opencvec.intra
   # OPENCVEC_CANARY_IP=10.0.5.20
   # OPENCVEC_PROOF_RESOLVERS=10.0.0.53     (votre DNS interne, pour l'auto-test)
   docker compose up -d
   ```
2. **Rediriger la zone canari vers OpenCVEC** sur le DNS interne : toutes les machines qui l'utilisent pourront alors « appeler » le canari.
   - Active Directory / DNS Windows :
     ```powershell
     Add-DnsServerConditionalForwarderZone -Name "canary.opencvec.intra" -MasterServers 10.0.5.20 -ReplicationScope Forest
     ```
   - Unbound (pfSense, OPNsense) :
     ```
     forward-zone:
       name: "canary.opencvec.intra"
       forward-addr: 10.0.5.20
     ```
   - BIND : `zone "canary.opencvec.intra" { type forward; forward only; forwarders { 10.0.5.20; }; };`
   - dnsmasq / AdGuard Home / Pi-hole : `server=/canary.opencvec.intra/10.0.5.20`
3. **Autoriser les plages internes** : Administration › Liste blanche (par exemple `10.0.0.0/16`, avec un motif).
4. **Vérifier** : Administration › Récepteur canari › Lancer l'auto-test. La ligne « Délégation via 10.0.0.53 » doit être en succès.

Un check « non concluant » en interne signifie souvent qu'un serveur n'utilise pas le DNS interne, ou que son trafic sortant est filtré. C'est une information utile en soi.

## Mode externe (Internet)

1. Un VPS avec une IP publique ; les ports **53/udp, 53/tcp et 80** doivent être ouverts.
2. Chez le registraire du domaine :
   ```
   c.opencvec.exemple.fr.    NS   ns1.opencvec.exemple.fr.
   ns1.opencvec.exemple.fr.  A    <IP publique>
   ```
3. Dans `.env` : `OPENCVEC_CANARY_ZONE=c.opencvec.exemple.fr`, `OPENCVEC_CANARY_IP=<IP publique>`, `OPENCVEC_NS_NAME=ns1.opencvec.exemple.fr`.
4. L'interface (port 8080) passe derrière un proxy HTTPS (Caddy, Traefik, nginx), avec `OPENCVEC_TRUST_PROXY=true` et `OPENCVEC_SECURE_COOKIES=true`. N'exposez pas l'interface sans filtrage : restreignez-la par VPN ou par adresse source.
5. Prouvez la propriété des assets par DNS TXT ou /.well-known, puis lancez l'auto-test.

## Architectures

L'image se construit pour amd64 et arm64 sans émulation :
```sh
docker buildx build --platform linux/amd64,linux/arm64 -t opencvec:latest .
```

## Sauvegarde

Ce qu'il faut sauvegarder :
- la base PostgreSQL (`docker compose exec db pg_dump -U opencvec opencvec > sauvegarde.sql`) ;
- la valeur de `OPENCVEC_SECRET_KEY`. Sans elle, les secrets TOTP et la clé HMAC des canaris deviennent illisibles, et l'instance ne démarre plus.
