<h1 align="center">OpenCVEC</h1>
<p align="center"><strong>CVE Checker</strong> : vérification de vulnérabilités par canari, auto-hébergée.</p>

OpenCVEC permet à une organisation de **prouver qu'une CVE touche ses propres assets** sans rien exploiter. Chaque check envoie un payload figé dont le seul effet possible est de faire résoudre à la cible un nom DNS unique : le **canari**. Si le récepteur intégré reçoit cette requête, la vulnérabilité est prouvée, avec une trace horodatée et signée.

L'outil est conçu pour ne pas pouvoir être retourné contre un tiers : pas de check sans preuve de propriété de l'asset, pas de payload ni d'URL de rappel modifiable, et des connexions sortantes confinées au périmètre prouvé.

Il vise les organisations à petit budget : un conteneur de 7 Mo qui occupe environ 11 Mio de RAM au repos, plus PostgreSQL. Il s'installe dans le SI ou sur un VPS (voir [docs/deploiement.md](docs/deploiement.md)). Les nouvelles CVE s'ajoutent par **plugins signés**, sans mise à jour de l'application.

## Fonctionnement

1. **Déclarer un asset** (nom de domaine, IP ou plage) et **prouver sa propriété** :
   - enregistrement DNS `TXT _opencvec.<hôte>` validé par la majorité des résolveurs interrogés ;
   - fichier `/.well-known/opencvec-<id>.txt` servi par l'hôte ;
   - ou, pour un réseau interne, plage autorisée par un administrateur (motif obligatoire, revue tous les 90 jours au plus).

   La preuve dure 30 jours et est **revalidée avant chaque campagne**.
2. **Lancer un check** : OpenCVEC émet un canari `<point>.<jeton>.<zone>`. Le jeton vaut `nonce ‖ HMAC(clé, asset ‖ check ‖ nonce)`. Il est à usage unique et expire après 15 minutes.
3. **Recevoir le callback** : le serveur DNS autoritaire intégré (et un récepteur HTTP) enregistre la requête. Le premier callback valide donne le verdict **prouvé**, avec l'IP source, le type de requête, le point d'injection et le délai. Sans callback dans le délai imparti, le verdict est **non concluant**.

Les requêtes reçues hors check (jeton inconnu ou forgé, canari expiré, rejeu après verdict) sont journalisées comme rejetées et ne produisent jamais de verdict.

### Canari fichier

Pour les failles qui donnent accès aux fichiers ou à l'exécution de code, l'entreprise dépose sur l'asset un **canari fichier**. C'est un fichier dont le contenu est un jeton unique, généré depuis la fiche de l'asset, avec la commande de dépôt pour Linux ou Windows. Le check exploite la faille uniquement pour **relire ce fichier**, et la preuve est obtenue sans toucher à rien d'autre :
- soit le jeton revient dans la réponse ;
- soit la cible l'exfiltre vers le récepteur DNS.

Le canari sert aussi de **jeton piège** : s'il est lu en dehors d'un check, OpenCVEC lève une alerte de compromission (tableau de bord, callbacks, journal d'audit).

## Plugins

Un plugin est un fichier YAML **signé** (Ed25519) qui décrit les étapes d'un check : requêtes HTTP ou échanges TCP/TLS, extractions, règle de version et mode de preuve. Il s'installe depuis **Plugins › Catalogue officiel**, par URL ou par fichier. Avant l'installation, l'administrateur voit le contenu complet, les étapes et le résultat de la vérification de signature.

- Le moteur impose le périmètre : une étape donne un chemin ou un port, jamais un hôte. Les variables sont limitées à la cible et aux canaris, et les champs inconnus sont refusés.
- Seuls les éditeurs de confiance sont acceptés. L'éditeur officiel est intégré, et chacun peut ajouter la clé de son équipe. Un plugin non signé exige le **mode développeur**, qui est journalisé.
- Retirer un éditeur ou désactiver un plugin le retire immédiatement du catalogue.
- Pour écrire, signer et publier un plugin : `opencvec plugin keygen | lint | sign | verify | index`. Voir [docs/plugins.md](docs/plugins.md).

| Plugin officiel | CVE | Preuve | Validation en labo |
|---|---|---|---|
| ApacheTraversalChecker | CVE-2021-41773 | canari fichier relu | prouvé sur httpd 2.4.49 (configuration vulnérable), non concluant sur 2.4.51 |
| SpringFunctionChecker | CVE-2022-22963 | callback DNS (SpEL) | prouvé sur Spring Cloud Function 3.2.2 |
| RegreSSHionChecker | CVE-2024-6387 | bannière SSH (TCP) | probable sur OpenSSH 9.6, corrigé sur 9.9 |

## Checkers intégrés

| Checker | CVE | Mode | Validation en labo |
|---|---|---|---|
| Log4JChecker | CVE-2021-44228, CVE-2021-45046 | canari (lookup JNDI) | prouvé sur Solr 8.11.0, non concluant sur 8.11.2 |
| Text4ShellChecker | CVE-2022-42889 | canari (`${dns:}`) | prouvé avec commons-text 1.9, non concluant avec 1.10.0 |
| ConfluenceChecker | CVE-2022-26134 | canari (OGNL limité à `InetAddress.getByName`) | non validé (licence requise) |
| PHPCGIChecker | CVE-2024-4577 | canari (`gethostbyname` via PHP-CGI) | non validé (cible Windows requise) |
| PHP2ShellChecker | CVE-2026-109618, CVE-2026-109619 | empreinte de version | probable sur PHP 8.3.20 |
| WP2ShellChecker | CVE-2026-63030, CVE-2026-60137 | empreinte de version | tests unitaires uniquement |
| FortiBleedChecker | campagne « FortiBleed » (CVE associées) | exposition des interfaces FortiGate | tests unitaires uniquement |

**Mode empreinte.** PHP2Shell et WP2Shell sont des chaînes d'exécution de code activement exploitées. Les prouver par canari exigerait un véritable exploit : OpenCVEC se limite donc à lire la version exposée, et le verdict est au mieux « probable ».

**FortiBleed** désigne une campagne de vol d'identifiants, pas une CVE. Le checker signale une interface d'administration ou un portail SSL-VPN FortiGate joignable (verdict « exposé »).

Verdicts possibles : prouvé, probable, exposé, version corrigée, non concluant, erreur.

## Garde-fous

- **Preuve de propriété** obligatoire et revalidée au lancement. Retirer une plage de la liste blanche invalide les preuves qui en dépendent.
- **Payloads figés** : l'API refuse tout champ inconnu, ce qui rend impossible l'ajout d'un payload ou d'une URL de rappel personnalisés.
- **Garde réseau** : l'IP effectivement contactée est vérifiée à la connexion. Les adresses privées, de boucle locale ou de métadonnées cloud sont refusées hors liste blanche, et les redirections ne sont pas suivies, ce qui protège contre le rebinding DNS et l'usage comme rebond.
- **Limites de débit** par asset (par jour) et par utilisateur (par heure).
- **Rôles** administrateur, analyste et lecteur ; double authentification TOTP, imposable à tous.
- **Journal d'audit** en ajout seul : un déclencheur PostgreSQL interdit UPDATE et DELETE, et la chaîne d'empreintes SHA-256 est vérifiable depuis l'interface. Chaque refus y est inscrit.
- **Plugins signés** : éditeurs de confiance, revue avant installation, signature revérifiée à chaque chargement, aucune donnée de réponse conservée.
- **Rapports** HTML imprimables (PDF via le navigateur) ou JSON, dont l'empreinte SHA-256 est conservée par l'instance.

## Installation

Le guide complet, en mode interne (redirecteur DNS conditionnel, sans domaine public) ou externe (délégation NS), est dans [docs/deploiement.md](docs/deploiement.md). Démarrage rapide en mode externe : Docker, un nom de domaine dont vous pouvez déléguer une sous-zone, et les ports 53 (UDP et TCP) et 80 joignables depuis Internet.

```sh
cp .env.example .env    # puis renseigner les valeurs
docker compose up -d
```

Créez chez votre registraire la délégation de la zone canari vers le serveur :

```
c.opencvec.exemple.fr.    NS   ns1.opencvec.exemple.fr.
ns1.opencvec.exemple.fr.  A    <IP publique du serveur>
```

Ensuite, Administration › Récepteur canari › **Lancer l'auto-test** vérifie l'écoute locale et la délégation publique.

Le premier administrateur est créé au démarrage. Si `OPENCVEC_ADMIN_PASSWORD` est vide, son mot de passe aléatoire est affiché une seule fois dans les journaux. La commande `opencvec reset-admin <e-mail>` réinitialise un accès.

Placez l'interface (port 8080) derrière un proxy inverse HTTPS, avec `OPENCVEC_TRUST_PROXY=true` et `OPENCVEC_SECURE_COOKIES=true`.

### Variables d'environnement

| Variable | Rôle | Défaut |
|---|---|---|
| `OPENCVEC_DATABASE_URL` | connexion PostgreSQL | obligatoire |
| `OPENCVEC_SECRET_KEY` | clé AES-256 des secrets au repos (`openssl rand -base64 32`) | vide = secrets en clair |
| `OPENCVEC_CANARY_ZONE` | zone DNS déléguée au récepteur | `c.opencvec.local` |
| `OPENCVEC_CANARY_IP` | IP renvoyée pour les noms de la zone | `127.0.0.1` |
| `OPENCVEC_NS_NAME` | serveur de noms annoncé | `ns1.<zone>` |
| `OPENCVEC_DNS_ADDR` / `OPENCVEC_CANARY_HTTP_ADDR` | écoute DNS / HTTP du récepteur (`off` pour désactiver) | `:5353` / `:8081` |
| `OPENCVEC_PROOF_RESOLVERS` | résolveurs des preuves TXT et de l'auto-test | `1.1.1.1,8.8.8.8,9.9.9.9` |
| `OPENCVEC_PLUGIN_REGISTRY` | dépôt des plugins officiels (dossier contenant `index.json`) | dossier `plugins/` du dépôt GitHub |
| `OPENCVEC_ADMIN_EMAIL` / `OPENCVEC_ADMIN_PASSWORD` | premier administrateur | `admin@opencvec.local` |
| `OPENCVEC_REQUIRE_MFA` | double authentification obligatoire | `false` |
| `OPENCVEC_TRUST_PROXY`, `OPENCVEC_SECURE_COOKIES` | déploiement derrière HTTPS | `false` |

Les durées (vie du canari, attente du callback) et les limites de débit se règlent dans Administration.

## Labo de validation

`lab/compose.yaml` démarre OpenCVEC sur un réseau isolé, avec des cibles vulnérables et leurs versions corrigées. Les cibles résolvent les noms via le récepteur, donc aucun trafic de canari ne sort.

```sh
docker compose -f lab/compose.yaml up -d --build
./scripts/lab-e2e.sh            # checkers intégrés : 5 scénarios
./scripts/lab-plugins-e2e.sh    # plugins : 5 scénarios, plugin altéré refusé, alerte de jeton piège
```

L'interface du labo est servie sur http://127.0.0.1:8095 (identifiants dans `lab/compose.yaml`).

## Développement

```sh
docker run -d --name opencvec-testdb -e POSTGRES_USER=opencvec -e POSTGRES_PASSWORD=opencvec -e POSTGRES_DB=opencvec -p 55432:5432 postgres:17-alpine
export OPENCVEC_TEST_DATABASE_URL="postgres://opencvec:opencvec@127.0.0.1:55432/opencvec?sslmode=disable"
go test ./...                    # tests unitaires et d'intégration (preuve de bout en bout par DNS réel)
cd web && npm ci && npm test && npm run build
```

Pile : Go (API, récepteur DNS `miekg/dns`, runner), PostgreSQL, React et Vite (application embarquée dans le binaire), image distroless non root.

## Limites

Une preuve par canari n'est possible que si la faille permet de faire évaluer une donnée, de déclencher une connexion sortante ou de lire le canari fichier.
- Les fuites mémoire, les contournements d'authentification, les failles côté client et les escalades de privilèges locales ne se prouvent pas ainsi.
- Les corruptions mémoire exigeraient un véritable exploit : elles restent en mode empreinte.

Un « non concluant » ne veut pas dire « non vulnérable ». Il peut venir :
- d'un filtrage des sorties DNS ou HTTP ;
- d'un WAF ;
- d'un point d'injection non couvert ;
- d'un déclenchement différé (traitement des journaux plus tard).

Enfin, un équipement qui résout les noms vus dans le trafic (sandbox, EDR, passerelle de messagerie) peut déclencher un canari à la place de l'application. Le point d'injection et le délai aident à trancher.

## Usage responsable

N'utilisez OpenCVEC que sur des systèmes que votre organisation possède ou qu'elle est explicitement autorisée à tester. Voir [SECURITY.md](SECURITY.md).

## Licence

MIT
