# Sécurité

## Signaler une vulnérabilité

Ne publiez pas de ticket public. Utilisez la fonction « Report a vulnerability » (avis de sécurité privé) du dépôt GitHub. Indiquez la version, les étapes de reproduction et l'impact estimé.

## Modèle de menace

OpenCVEC envoie des requêtes vers des systèmes. Le risque principal est son détournement contre un système tiers. Les protections en place :

| Abus visé | Protection |
|---|---|
| Viser un système qui n'appartient pas à l'organisation | Preuve de propriété obligatoire (DNS TXT, /.well-known ou liste blanche administrateur), revalidée à chaque campagne |
| Faire exécuter une charge arbitraire | Payloads figés dans le code ; l'API refuse tout champ inconnu ; seul le nom du canari est injecté |
| Rebinding DNS, rebond vers le réseau interne ou les métadonnées cloud | IP vérifiée au moment de la connexion ; adresses privées et réservées refusées hors liste blanche ; redirections non suivies |
| Falsifier une preuve | Canari signé HMAC pour un couple asset × check, à usage unique, avec expiration ; rejeux et jetons forgés rejetés et journalisés |
| Masquer un usage abusif | Journal d'audit en ajout seul (déclencheur PostgreSQL) et chaîné par empreintes SHA-256 |
| Scan massif | Limites de débit par asset et par utilisateur |
| Plugin malveillant ou dépôt compromis | Signature Ed25519 obligatoire (éditeurs de confiance), revérifiée à chaque chargement ; contenu affiché avant installation ; mode développeur journalisé |
| Plugin qui vise un autre hôte ou exfiltre des données | Étapes limitées à un chemin ou un port de l'asset ; variables limitées à la cible et aux canaris ; corps des réponses jamais conservés |
| Compromission réelle d'un asset | Canari fichier = jeton piège : lu hors d'un check, il lève une alerte |

Le checker WP2Shell vérifie des CVE d'exécution de code récentes et exploitées. Il ne contient volontairement aucun exploit : il se limite à l'empreinte de version. PHP2Shell est traité de la même façon.

## Durcissement recommandé

- Définir `OPENCVEC_SECRET_KEY` : sans elle, les secrets TOTP et la clé HMAC des canaris sont stockés en clair.
- Imposer la double authentification (`OPENCVEC_REQUIRE_MFA=true`).
- Garder la clé privée de signature des plugins hors du dépôt et de l'instance (poste de l'éditeur, coffre-fort).
- Servir l'interface uniquement en HTTPS, derrière un proxy inverse, et ne pas l'exposer à Internet si possible. Seuls les ports 53 et 80 du récepteur doivent l'être.
