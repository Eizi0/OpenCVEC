// Traduction de l'interface. Le français est la langue source : les textes sont écrits en français
// dans les composants et traduits à l'affichage. En anglais, un observateur remplace les textes
// connus (dictionnaire exact, puis motifs à variables) dans les nœuds de texte et les attributs
// accessibles. Le contenu technique et les données (code, valeurs en police mono, champs de saisie,
// éléments marqués data-no-i18n) n'est jamais traduit.

export type Lang = 'fr' | 'en'

const KEY = 'opencvec.lang'

export function getLang(): Lang {
  try {
    const v = localStorage.getItem(KEY)
    if (v === 'fr' || v === 'en') return v
  } catch { /* stockage indisponible */ }
  return typeof navigator !== 'undefined' && navigator.language?.toLowerCase().startsWith('fr') ? 'fr' : 'en'
}

export function setLang(l: Lang) {
  try { localStorage.setItem(KEY, l) } catch { /* stockage indisponible */ }
  window.location.reload()
}

const dict: Record<string, string> = {
  // Navigation et structure
  "Vue d'ensemble": 'Overview', 'Assets': 'Assets', 'Catalogue des checkers': 'Checker catalog', 'Checks': 'Checks',
  'Vérifier': 'Verify', 'Tracer': 'Trace', 'Callbacks canari': 'Canary callbacks', 'Rapports': 'Reports',
  "Journal d'audit": 'Audit log', 'Plugins': 'Plugins', 'Administration': 'Administration', 'Mon compte': 'My account',
  'Récepteur canari': 'Canary receiver', 'DNS + HTTP actifs': 'DNS + HTTP up', 'Se déconnecter': 'Sign out',
  'Navigation principale': 'Main navigation', "Fil d'Ariane": 'Breadcrumb', 'Chargement…': 'Loading…', 'Erreur': 'Error',
  'Administrateur': 'Administrator', 'Analyste': 'Analyst', 'Lecteur': 'Viewer', 'Copier': 'Copy', 'Copié': 'Copied',
  'Annuler': 'Cancel', 'Enregistrer': 'Save', 'Modifier': 'Edit', 'Supprimer': 'Delete', 'Retirer': 'Remove',
  'Activer': 'Enable', 'Désactiver': 'Disable', 'Réactiver': 'Re-enable', 'Ouvrir': 'Open', 'Créer': 'Create',
  'Configurer': 'Set up', 'Générer': 'Generate', 'Examiner': 'Review', 'Approuver': 'Approve', 'Autoriser': 'Allow',
  'Réinitialiser': 'Reset', 'Révoquer': 'Revoke', 'Vérifier maintenant': 'Verify now', 'Vérification…': 'Checking…',
  'Tous': 'All', 'Toutes': 'All', 'Tout': 'All', 'Aucune': 'None', 'Statut': 'Status', 'Action': 'Action', 'Actions': 'Actions',
  'Détail': 'Detail', 'Détails': 'Details', 'Type': 'Type', 'Nom': 'Name', 'Rôle': 'Role', 'Quand': 'When', 'Source': 'Source',
  'Préfixe': 'Prefix', 'Expiration': 'Expiry', 'Zone': 'Zone', 'Chemin': 'Path', 'Contenu': 'Content', 'Valeur': 'Value',
  'Port': 'Port', 'Produit': 'Product', 'Preuve': 'Proof', 'Envoyé': 'Sent', 'Module': 'Module', 'Prérequis': 'Requirement',
  'Plugin': 'Plugin', 'Signature': 'Signature', 'Éditeur': 'Publisher', 'Clé': 'Key', 'Format': 'Format', 'Rapport': 'Report',
  'Résultat': 'Result', 'Lancée par': 'Launched by', 'Campagne': 'Campaign', 'Asset': 'Asset', 'Checker': 'Checker',
  'Verdict': 'Verdict', 'Utilisateur': 'User', 'Horodatage': 'Timestamp', 'Période': 'Period', 'Motif': 'Reason',
  'Revue': 'Review', 'Plage': 'Range', 'Ajoutée par': 'Added by', 'Ajouté': 'Added', 'Installé': 'Installed', 'Créé': 'Created',
  'Reçu': 'Received', 'Proto': 'Proto', 'Nom interrogé': 'Queried name', 'Corrélation': 'Correlation', 'Fichier': 'File',
  'Étapes': 'Steps', 'Fréquence': 'Frequency', 'Prochaine exécution': 'Next run', 'Dernière': 'Last', 'Sécurité': 'Security',
  'Expéditeur': 'Sender', 'Schéma': 'Scheme', 'Tags': 'Tags', 'Propriété': 'Ownership', 'Dernier verdict': 'Last verdict',
  'Méthode de preuve': 'Proof method', 'Dernière connexion': 'Last sign-in', 'Dernière utilisation': 'Last used',
  'Nouveau rapport': 'New report', 'Périmètre': 'Scope', 'Tous les assets': 'All assets', 'Campagnes': 'Campaigns',

  // Verdicts et statuts
  'Prouvé vulnérable': 'Proven vulnerable', 'Probable': 'Probable', 'Exposé': 'Exposed', 'Version corrigée': 'Patched version',
  'Non concluant': 'Inconclusive', 'Aucun check': 'No check', 'En file': 'Queued', 'Envoi': 'Sending',
  'En attente du canari': 'Waiting for canary', 'Terminé': 'Done', 'Annulé': 'Cancelled', 'Annulée': 'Cancelled',
  'Corrélé': 'Correlated', 'Doublon': 'Duplicate', 'Rejeté (expiré)': 'Rejected (expired)', 'Rejeté (rejeu)': 'Rejected (replay)',
  'Rejeté (jeton inconnu)': 'Rejected (unknown token)', 'Auto-test': 'Self-test',
  'Alerte : canari fichier lu hors check': 'Alert: canary file read outside a check',
  'DNS TXT': 'DNS TXT', 'Liste blanche admin': 'Admin allowlist', 'Domaine': 'Domain', 'Adresse IP': 'IP address',
  'Prouvée': 'Proven', 'Autorisée': 'Allowed', 'À renouveler': 'To renew', 'Échec': 'Failed', 'Expirée': 'Expired',
  'En attente': 'Pending', 'preuve à refaire': 'proof to redo', 'preuve non vérifiée': 'proof not verified',
  'Canari': 'Canary', 'Empreinte': 'Fingerprint', 'Intégré': 'Built-in', 'Validé en labo': 'Lab-validated',
  'Non validé en labo': 'Not lab-validated', 'En écoute': 'Listening', 'Arrêté': 'Stopped', 'Activé': 'Enabled', 'Activée': 'Enabled',
  'À configurer': 'To set up', 'jamais': 'never', 'à l’instant': 'just now', 'hier': 'yesterday', 'suspendu': 'paused',

  // Connexion
  'Prouvez votre exposition.': 'Prove your exposure.', 'Sans rien exploiter.': 'Without exploiting anything.',
  "Chaque check pousse la cible à appeler un canari unique, lié à un asset dont vous avez prouvé la propriété. Pas de shell, pas de charge modifiable : un appel DNS ou HTTP suffit comme preuve.":
    'Each check makes the target call a unique canary, bound to an asset whose ownership you proved. No shell, no editable payload: a DNS or HTTP call is enough as proof.',
  "Prouver la propriété de l’asset (TXT, /.well-known ou liste blanche)": 'Prove ownership of the asset (TXT, /.well-known or allowlist)',
  'Émettre un canari à usage unique pour ce check': 'Issue a single-use canary for this check',
  'Recevoir le callback : verdict et preuve horodatée': 'Receive the callback: verdict and timestamped proof',
  'Instance auto-hébergée': 'Self-hosted instance', 'Connexion': 'Sign in', 'Double authentification': 'Two-factor authentication',
  'Adresse e-mail': 'Email address', 'Mot de passe': 'Password', 'Code TOTP': 'TOTP code', '6 chiffres': '6 digits',
  'Valider': 'Confirm', 'Se connecter': 'Sign in',
  "Toute action est inscrite au journal d'audit. L'usage est limité aux assets dont votre organisation a prouvé la propriété.":
    'Every action is written to the audit log. Use is limited to assets whose ownership your organization has proven.',

  // Tableau de bord
  'Exposition prouvée de vos assets, sur les 30 derniers jours.': 'Proven exposure of your assets over the last 30 days.',
  'Lancer un check': 'Launch a check', 'Assets à propriété prouvée': 'Assets with proven ownership',
  'aucune preuve à renouveler': 'no proof to renew', 'Checks exécutés': 'Checks run', 'Vulnérabilités prouvées': 'Proven vulnerabilities',
  'canari déclenché par la cible': 'canary triggered by the target', 'Probables ou exposés': 'Probable or exposed',
  'version ou surface exposée, sans preuve active': 'exposed version or surface, without active proof',
  'Derniers verdicts': 'Latest verdicts', 'Tous les checks': 'All checks', 'Aucun check pour l\'instant. Commencez par': 'No check yet. Start by',
  'déclarer un asset': 'declaring an asset', 'Dernier callback': 'Last callback', 'Voir le journal des callbacks': 'View the callback log',
  'Preuves à faire ou renouveler': 'Proofs to do or renew', 'Toutes les preuves sont valides.': 'All proofs are valid.',
  'Gérer les assets': 'Manage assets', 'échec': 'failed', 'à prouver': 'to prove',
  "Canari fichier lu hors d'un check : compromission probable": 'Canary file read outside a check: probable compromise',
  "Le contenu du fichier canari, connu seulement d'OpenCVEC et de la machine, a été lu puis transmis.":
    'The canary file content, known only to OpenCVEC and the machine, was read and sent out.',
  'Voir les alertes': 'View alerts',

  // Assets
  'Seuls les assets à propriété prouvée peuvent être vérifiés. La preuve expire au bout de 30 jours et est revalidée avant chaque campagne.':
    'Only assets with proven ownership can be checked. Proof expires after 30 days and is re-validated before every campaign.',
  'Ajouter un asset': 'Add an asset', 'Filtrer par statut': 'Filter by status', 'Rechercher un asset': 'Search an asset',
  'Rechercher un domaine, une IP, un tag…': 'Search a domain, an IP, a tag…', 'Aucun asset.': 'No asset.',
  'Les plages privées (RFC 1918) et les adresses internes ne passent que par la liste blanche gérée en Administration ; chaque ajout est journalisé.':
    'Private ranges (RFC 1918) and internal addresses only go through the allowlist managed in Administration; every addition is logged.',
  'Nouvel asset': 'New asset', "Nom d'hôte, IP ou plage CIDR": 'Hostname, IP or CIDR range', 'Tags (séparés par des virgules)': 'Tags (comma-separated)',
  'Schéma par défaut': 'Default scheme', 'Port (vide = par défaut)': 'Port (empty = default)',
  'Enregistrement DNS TXT': 'DNS TXT record', 'Recommandé pour un nom de domaine public': 'Recommended for a public domain name',
  'Fichier /.well-known': '/.well-known file', 'Servi par le site lui-même': 'Served by the site itself', 'Liste blanche': 'Allowlist',
  'Réseau interne autorisé par un administrateur': 'Internal network allowed by an administrator', "Déclarer l'asset": 'Declare the asset',
  'Pourquoi cette étape ?': 'Why this step?',
  "Sans preuve, OpenCVEC refuse tout check. Cela empêche d'utiliser la plateforme contre un système qui ne vous appartient pas.":
    'Without proof, OpenCVEC refuses any check. This prevents using the platform against a system you do not own.',
  'Ce qui est contrôlé': 'What is checked', 'Le jeton est présent et identique.': 'The token is present and identical.',
  'La majorité des résolveurs publics voient le même enregistrement.': 'A majority of public resolvers see the same record.',
  'La preuve est revalidée avant chaque campagne.': 'Proof is re-validated before every campaign.',
  "Les adresses contactées restent dans le périmètre de l'asset.": 'Contacted addresses stay within the asset scope.',
  'Preuve de propriété': 'Proof of ownership', 'Ajoutez cet enregistrement à votre zone DNS': 'Add this record to your DNS zone',
  'Publiez ce fichier sur le serveur': 'Publish this file on the server', 'Jeton à publier avant le': 'Token to publish before',
  "L'asset doit appartenir entièrement à une plage autorisée par un administrateur (Administration › Liste blanche). La preuve dure au plus jusqu'à la date de revue de la plage.":
    "The asset must fully belong to a range allowed by an administrator (Administration › Allowlist). Proof lasts at most until the range's review date.",
  'Propriété prouvée': 'Ownership proven', 'Preuve refusée': 'Proof rejected', 'Preuve à refaire': 'Proof to redo',
  'Vérifiée le': 'Verified on', 'Régénérer le jeton': 'Regenerate the token', 'URL par défaut': 'Default URL',
  'Adresses résolues': 'Resolved addresses', 'Déclaré le': 'Declared on', 'Campagnes récentes': 'Recent campaigns',
  'Aucune campagne.': 'No campaign.', 'Changer le schéma ou le port impose de refaire la preuve.': 'Changing the scheme or port requires redoing the proof.',
  'Canari fichier': 'Canary file',
  "Un fichier au contenu unique, déposé sur la machine. Les plugins d'exploitation prouvent la faille en le relisant ou en l'exfiltrant vers le récepteur, sans toucher à rien d'autre. Lu en dehors d'un check, il déclenche une alerte de compromission.":
    'A file with unique content, planted on the machine. Exploitation plugins prove the flaw by reading it back or exfiltrating it to the receiver, without touching anything else. Read outside a check, it raises a compromise alert.',
  "Dépôt sur l'asset": 'Deployment on the asset', 'Télécharger le fichier': 'Download the file', 'Changer / renouveler': 'Change / renew',
  "Chemin absolu sur l'asset": 'Absolute path on the asset', 'Générer le canari': 'Generate the canary',
  'Générer un nouveau jeton': 'Generate a new token', 'Aucun canari fichier déposé.': 'No canary file planted.',
  'Nouveau jeton généré : publiez-le puis vérifiez.': 'New token generated: publish it, then verify.',

  // Catalogue et plugins
  "Tous les checkers sont des plugins signés : les officiels sont préinstallés, d'autres s'ajoutent depuis la page Plugins. Les payloads sont figés dans chaque module : seul le nom d'hôte du canari y est injecté. Les failles qu'on ne peut prouver sans exploit réel (corruption mémoire, chaînes RCE récentes) sont vérifiées par empreinte, sans aucune charge.":
    'Every checker is a signed plugin: official ones are preinstalled, others are added from the Plugins page. Payloads are fixed in each module: only the canary hostname is injected. Flaws that cannot be proven without a real exploit (memory corruption, recent RCE chains) are verified by fingerprint, with no payload.',
  'Filtrer par mode': 'Filter by mode', "Canari fichier déposé sur l'asset": 'Canary file planted on the asset',
  'Remédiation et références': 'Remediation and references', 'Utiliser ce checker': 'Use this checker',
  "Ajoutez un check pour une nouvelle CVE sans mettre à jour OpenCVEC. Un plugin est un fichier YAML signé : ses requêtes ne peuvent viser que l'asset du check, et la preuve passe toujours par un canari (callback DNS/HTTP ou canari fichier relu).":
    "Add a check for a new CVE without updating OpenCVEC. A plugin is a signed YAML file: its requests can only target the check's asset, and proof always goes through a canary (DNS/HTTP callback or canary file read back).",
  'Installés': 'Installed', 'Catalogue officiel': 'Official catalog', 'Importer': 'Import', 'Éditeurs de confiance': 'Trusted publishers',
  'Aucun plugin installé. Parcourez le catalogue officiel ou importez un fichier.': 'No plugin installed. Browse the official catalog or import a file.',
  'Non signé': 'Unsigned', 'Voir le YAML': 'View YAML', 'Masquer': 'Hide', 'Désinstaller': 'Uninstall', 'Catalogue injoignable': 'Catalog unreachable',
  "Sans accès Internet, téléchargez le plugin et sa signature (.sig) depuis le dépôt GitHub, puis utilisez l'onglet « Importer ». L'adresse du catalogue se règle avec OPENCVEC_PLUGIN_REGISTRY.":
    'Without Internet access, download the plugin and its signature (.sig) from the GitHub repository, then use the "Import" tab. The catalog address is set with OPENCVEC_PLUGIN_REGISTRY.',
  'Dépôt :': 'Repository:', 'Installé · revoir': 'Installed · review', 'Examiner et installer': 'Review and install',
  'Source du plugin': 'Plugin source', 'URL https du fichier YAML': 'HTTPS URL of the YAML file',
  'La signature est cherchée à la même adresse, suffixée de « .sig ».': 'The signature is fetched from the same address, with a ".sig" suffix.',
  'ou fichiers locaux': 'or local files', 'Plugin (.yaml)': 'Plugin (.yaml)', 'Signature (.sig)': 'Signature (.sig)',
  'Revue avant installation': 'Review before installation',
  "Choisissez un plugin : son contenu, ses étapes et sa signature s'affichent ici avant toute installation.":
    'Choose a plugin: its content, steps and signature are shown here before any installation.',
  'Non signé ou signature refusée': 'Unsigned or signature rejected',
  "Le mode développeur est actif : l'installation reste possible et sera journalisée.": 'Developer mode is on: installation remains possible and will be logged.',
  'Mise à jour': 'Update', 'Remplace la version': 'Replaces version', 'installée.': 'currently installed.', 'Envoyé à la cible': 'Sent to the target',
  'Requis : à déposer sur chaque asset testé': 'Required: to plant on every tested asset', 'Non requis': 'Not required',
  'Contenu complet du plugin': 'Full plugin content', 'Installer': 'Install', 'Mettre à jour': 'Update', 'Installation…': 'Installing…',
  'Équipe sécurité interne': 'Internal security team', 'Clé publique': 'Public key', 'intégré': 'built-in', 'installation': 'installation',

  // Checks
  'Un canari distinct est émis pour chaque couple asset × checker. La propriété de l\'asset est revalidée juste avant l\'envoi.':
    "A distinct canary is issued for each asset × checker pair. The asset's ownership is re-validated right before sending.",
  '1. Asset cible': '1. Target asset', '2. Checkers': '2. Checkers', 'Propriété non prouvée': 'Ownership not proven',
  'URL cible': 'Target URL', '(une adresse de la plage)': '(an address in the range)', 'Doit viser': 'Must target',
  '. Le chemin et le port sont libres : visez la page qui traite les entrées (formulaire, API…).': '. Path and port are free: target the page that processes input (form, API…).',
  'suggéré': 'suggested', 'canari fichier requis': 'canary file required', 'plugin': 'plugin',
  "Suggestions d'après les tags de l'asset. Le contenu des payloads n'est pas modifiable.": "Suggestions based on the asset's tags. Payload content cannot be edited.",
  "Avant l'envoi": 'Before sending', 'Propriété revalidée au lancement': 'Ownership re-validated at launch',
  "Adresses contactées limitées à l'asset": 'Contacted addresses limited to the asset', 'Limites de débit par asset et par utilisateur': 'Rate limits per asset and per user',
  "Action inscrite au journal d'audit": 'Action written to the audit log', 'Canaris émis': 'Canaries issued', '(usage unique)': '(single use)',
  'Durée de vie': 'Lifetime', 'Attente du callback': 'Callback wait', 'Répétition': 'Repetition', 'Une seule fois': 'Once',
  'Maintenant, puis chaque semaine': 'Now, then every week', 'Maintenant, puis chaque mois': 'Now, then every month',
  'Maintenant, puis chaque trimestre': 'Now, then every quarter',
  'Chaque exécution programmée revalide la propriété et respecte les limites, comme un lancement manuel.':
    'Every scheduled run re-validates ownership and respects limits, like a manual launch.',
  'Revalidation de la propriété…': 'Re-validating ownership…',
  'Historique des campagnes. Une campagne regroupe les checks lancés ensemble sur un asset.': 'Campaign history. A campaign groups the checks launched together on an asset.',
  'Checks programmés': 'Scheduled checks', 'Suspendre': 'Pause', 'Supprimer cette programmation ?': 'Delete this schedule?',
  'sans preuve': 'without proof', 'Annuler la campagne': 'Cancel the campaign', 'Générer le rapport': 'Generate the report',
  'Canari de ce check': 'Canary of this check', 'Propriété revalidée, cible résolue': 'Ownership re-validated, target resolved',
  'Canari émis': 'Canary issued', 'Payload envoyé': 'Payload sent', 'En attente du callback': 'Waiting for the callback',
  'DNS et HTTP surveillés': 'DNS and HTTP watched', "Lecture de l’empreinte": 'Reading the fingerprint', 'aucune charge envoyée': 'no payload sent',
  'Voir le verdict et la preuve': 'View the verdict and proof', 'Événements du récepteur': 'Receiver events', '(en direct)': '(live)',
  'Aucun callback reçu pour cette campagne.': 'No callback received for this campaign.',
  'Relancer après correctif': 'Re-run after fix', 'Check en cours.': 'Check in progress.', 'Preuve du callback': 'Callback proof',
  'Empreinte relevée': 'Fingerprint read', 'Adresses contactées': 'Contacted addresses', 'Lié à': 'Bound to', '(signature HMAC)': '(HMAC signature)',
  'Type de requête': 'Request type', "Point d'injection": 'Injection point', 'Réception': 'Received', 'Verdict rendu': 'Verdict given',
  'Remédiation': 'Remediation', 'Ce qui a été envoyé': 'What was sent',

  // Traçabilité
  'Tout ce que reçoit le récepteur, y compris les requêtes rejetées (jeton inconnu, expiré ou rejoué). Les requêtes rejetées ne produisent jamais de verdict.':
    'Everything the receiver gets, including rejected requests (unknown, expired or replayed token). Rejected requests never produce a verdict.',
  'Corrélés': 'Correlated', 'Rejetés': 'Rejected', 'Alertes': 'Alerts', 'Auto-tests': 'Self-tests', 'Aucun callback.': 'No callback.',
  'jeton inconnu ou signature invalide': 'unknown token or invalid signature', 'auto-test du récepteur': 'receiver self-test',
  'lu hors check': 'read outside a check', 'canari fichier de': 'canary file of',
  'Un pic de jetons inconnus peut signaler un scan de la zone canari. Leur enregistrement est limité à 120 par minute.':
    'A spike of unknown tokens may indicate a scan of the canary zone. Their recording is limited to 120 per minute.',
  "Chaque rapport embarque les preuves (canari, horodatages, source, requête brute) et son empreinte SHA-256 est conservée par l'instance.":
    'Each report embeds the proofs (canary, timestamps, source, raw request), and its SHA-256 fingerprint is kept by the instance.',
  'Période (jours)': 'Period (days)', 'Inclure les requêtes brutes reçues': 'Include raw requests received',
  'Inclure les checks non concluants et en erreur': 'Include inconclusive and failed checks', 'Génération…': 'Generating…',
  'Rapports générés': 'Generated reports', 'Aucun rapport.': 'No report.', 'Contenu ': 'Content',
  'En ajout seul, chaîné par empreinte : une ligne modifiée ou supprimée casse la chaîne.': 'Append-only, hash-chained: a modified or deleted line breaks the chain.',
  'Exporter (JSONL)': 'Export (JSONL)', '24 heures': '24 hours', '7 jours': '7 days', '30 jours': '30 days', 'Aucune entrée.': 'No entry.',
  'Check lancé': 'Check launched', 'Refus': 'Refusal', 'Connexion refusée': 'Sign-in refused', 'Asset déclaré': 'Asset declared',
  'Rôle modifié': 'Role changed', 'Utilisateur créé': 'User created', 'Réglages modifiés': 'Settings changed',

  // Administration
  'Utilisateurs et rôles': 'Users and roles', 'Liste blanche réseau interne': 'Internal network allowlist',
  'Récepteur canari et limites': 'Canary receiver and limits', 'Notifications': 'Notifications',
  'Administrateur : tout. Analyste : assets, checks, rapports. Lecteur : consultation seule.': 'Administrator: everything. Analyst: assets, checks, reports. Viewer: read-only.',
  'E-mail': 'Email', 'Créer le compte': 'Create account', 'TOTP': 'TOTP',
  'Communiquez-le par un canal sûr : il ne sera plus affiché.': 'Share it through a secure channel: it will not be shown again.',
  "Les adresses privées ne peuvent pas prouver leur propriété par DNS public. Seul un administrateur peut les autoriser : un motif est exigé et une revue a lieu au plus tous les 90 jours. Une plage expirée ou retirée invalide les preuves qui en dépendent.":
    'Private addresses cannot prove ownership through public DNS. Only an administrator can allow them: a reason is required and a review happens at least every 90 days. An expired or removed range invalidates the proofs that depend on it.',
  'Plage CIDR': 'CIDR range', 'Ex. : serveurs applicatifs du site de Lyon': 'E.g.: application servers of the Lyon site',
  'Revue (jours)': 'Review (days)', 'Aucune plage autorisée.': 'No allowed range.', 'Prolonger 30 j': 'Extend 30 days', 'expirée': 'expired',
  'Zone canari déléguée': 'Delegated canary zone', 'Serveur de noms annoncé': 'Announced name server', 'Adresse du récepteur': 'Receiver address',
  'Enregistrements à créer dans la zone parente': 'Records to create in the parent zone',
  "Se règle par variables d'environnement (OPENCVEC_CANARY_ZONE, OPENCVEC_CANARY_IP, OPENCVEC_NS_NAME). Les ports 53 (UDP et TCP) et 80 doivent être joignables depuis Internet.":
    'Set through environment variables (OPENCVEC_CANARY_ZONE, OPENCVEC_CANARY_IP, OPENCVEC_NS_NAME). Ports 53 (UDP and TCP) and 80 must be reachable from the Internet.',
  'Canaris, limites et plugins': 'Canaries, limits and plugins', 'Durée de vie du canari (min)': 'Canary lifetime (min)',
  'Attente du callback (s)': 'Callback wait (s)', 'Checks par asset et par jour': 'Checks per asset per day',
  'Checks par utilisateur et par heure': 'Checks per user per hour', 'Conservation (jours, 0 = illimitée)': 'Retention (days, 0 = unlimited)',
  "Bruit du récepteur et rapports. Preuves, alertes, checks et journal d'audit sont toujours conservés.": 'Receiver noise and reports. Proofs, alerts, checks and the audit log are always kept.',
  'Mode développeur': 'Developer mode', ': autoriser les plugins non signés.': ': allow unsigned plugins.',
  "Réservé à l'écriture et au test de plugins. Activation, désactivation et chaque installation non signée sont journalisées.":
    'For writing and testing plugins only. Turning it on or off and every unsigned installation are logged.',
  'Réglages enregistrés.': 'Settings saved.', 'Auto-test du récepteur': 'Receiver self-test', 'OK': 'OK',
  "Lancer l’auto-test": 'Run the self-test', 'Test en cours (jusqu’à 20 s)…': 'Testing (up to 20 s)…',
  "Vérifie l'écoute locale, puis la délégation publique en interrogeant les résolveurs configurés : un échec de ces derniers signale une délégation NS absente ou un port 53 fermé.":
    'Checks local listening, then public delegation by querying the configured resolvers: a failure there signals a missing NS delegation or a closed port 53.',
  'Webhook': 'Webhook', 'URL': 'URL', 'JSON générique': 'Generic JSON', 'Slack': 'Slack', 'Teams': 'Teams',
  "Slack, Microsoft Teams (Incoming Webhook / Workflows), SIEM ou n'importe quel point de collecte JSON.": 'Slack, Microsoft Teams (Incoming Webhook / Workflows), a SIEM or any JSON collector.',
  'Destinataires (séparés par des virgules)': 'Recipients (comma-separated)', 'Serveur SMTP': 'SMTP server', 'STARTTLS': 'STARTTLS', 'TLS': 'TLS',
  "Le mot de passe est chiffré au repos et n'est jamais réaffiché.": 'The password is encrypted at rest and never shown again.',
  'Événements notifiés': 'Notified events', 'Canari fichier lu hors check (compromission probable)': 'Canary file read outside a check (probable compromise)',
  'Vulnérabilité prouvée': 'Proven vulnerability', 'Verdict probable ou exposé': 'Probable or exposed verdict',
  "Échec d'un check programmé": 'Scheduled check failure', 'Envoyer un test': 'Send a test', 'Notifications enregistrées.': 'Notifications saved.',

  // Compte
  'Double authentification obligatoire': 'Two-factor authentication required',
  "Activez-la ci-dessous pour accéder au reste de l'application.": 'Turn it on below to access the rest of the application.',
  'Double authentification (TOTP)': 'Two-factor authentication (TOTP)', 'Un code est demandé à chaque connexion.': 'A code is asked at every sign-in.',
  'Mot de passe pour désactiver': 'Password to disable',
  "Protégez votre compte avec une application d'authentification (Aegis, 2FAS, Google Authenticator…).": 'Protect your account with an authenticator app (Aegis, 2FAS, Google Authenticator…).',
  "QR code à scanner avec l'application d'authentification": 'QR code to scan with the authenticator app', 'Ou saisissez la clé :': 'Or enter the key:',
  'Code affiché': 'Displayed code', 'Mot de passe actuel': 'Current password', 'Nouveau mot de passe (12 caractères minimum)': 'New password (12 characters minimum)',
  'Mot de passe modifié. Vos autres sessions ont été fermées.': 'Password changed. Your other sessions were closed.',
  "Jetons d'API": 'API tokens', 'Pour automatiser OpenCVEC (CI, scripts) : en-tête': 'To automate OpenCVEC (CI, scripts): header',
  ". Un jeton a les droits de votre compte, mais ne peut ni créer d'autres jetons ni modifier votre mot de passe ou votre double authentification.":
    '. A token has the rights of your account, but can neither create other tokens nor change your password or two-factor authentication.',
  'Expiration (jours, 0 = jamais)': 'Expiry (days, 0 = never)', 'Copiez ce jeton maintenant : il ne sera plus affiché.': 'Copy this token now: it will not be shown again.',
  // Fragments de phrases découpées autour d'une valeur
  ". Après un renouvellement, redéposez le fichier : l'ancien contenu ne prouve plus rien.": '. After a renewal, plant the file again: the old content no longer proves anything.',
  '/ Campagne #': '/ Campaign #', '/ Nouvel asset': '/ New asset', 'Campagne #': 'Campaign #', 'Chaîne intègre ·': 'Intact chain ·',
  "Chaîne rompue à l'entrée #": 'Chain broken at entry #', 'DNS autoritaire ·': 'Authoritative DNS ·', 'Déclarez-en un': 'Declare one',
  'Généré le': 'Generated on', 'Requêtes reçues (': 'Requests received (', "Points d'injection (": 'Injection points (', 'Rôle de': 'Role of',
  'Linux : /opt/opencvec/canary.txt · Windows : C:\\ProgramData\\OpenCVEC\\canary.txt. Le fichier doit être lisible par le service testé.':
    'Linux: /opt/opencvec/canary.txt · Windows: C:\\ProgramData\\OpenCVEC\\canary.txt. The file must be readable by the tested service.',
  'Seuls les plugins signés par un éditeur listé ici sont installés et chargés. Retirer un éditeur désactive aussitôt ses plugins. Pour signer vos propres plugins :':
    'Only plugins signed by a publisher listed here are installed and loaded. Removing a publisher immediately disables its plugins. To sign your own plugins:',
  'Signature valide ·': 'Valid signature ·', 'Signé ·': 'Signed ·', 'en cours': 'running', 'en mode empreinte': 'in fingerprint mode',
  'dont': 'of which', 'entrées': 'entries', 'et prouvez sa propriété.': 'and prove its ownership.', 'prouvé(s)': 'proven',
  'probable(s)': 'probable', 'requête(s) depuis': 'request(s) from', 'tous les': 'every', 'j': 'days', '· campagne #': '· campaign #',
  '· check #': '· check #', '· dernière lecture': '· last read', '· lancée par': '· launched by', '· preuve par': '· proof by',
  '· éditeur': '· publisher', 'le': 'on',
}

const patterns: [RegExp, string][] = [
  [/^il y a (\d+) s$/, '$1 s ago'], [/^il y a (\d+) min$/, '$1 min ago'], [/^il y a (\d+) h$/, '$1 h ago'], [/^il y a (\d+) j$/, '$1 days ago'],
  [/^expire dans (-?\d+) j$/, 'expires in $1 days'], [/^dans (-?\d+) j$/, 'in $1 days'], [/^tous les (\d+) j$/, 'every $1 days'],
  [/^· (\d+) en cours$/, '· $1 running'], [/^Tous · (\d+)$/, 'All · $1'], [/^Prouvés · (\d+)$/, 'Proven · $1'], [/^À renouveler · (\d+)$/, 'To renew · $1'],
  [/^En attente \/ échec · (\d+)$/, 'Pending / failed · $1'], [/^Preuve par canari · (\d+)$/, 'Canary proof · $1'],
  [/^Empreinte seule · (\d+)$/, 'Fingerprint only · $1'], [/^Prouvée · (\d+) j restants$/, 'Proven · $1 days left'],
  [/^(\d+) preuve\(s\) à renouveler sous 7 j$/, '$1 proof(s) to renew within 7 days'],
  [/^dont (\d+) en mode empreinte(?: · (\d+) en cours)?$/, '$1 in fingerprint mode'],
  [/^Lancer (\d+) checks?$/, 'Launch $1 check(s)'], [/^(\d+) en cours$/, '$1 running'], [/^(\d+) prouvé\(s\)$/, '$1 proven'],
  [/^(\d+) probable\(s\)$/, '$1 probable'], [/^(\d+) sans preuve$/, '$1 without proof'],
  [/^(\d+) prouvé\(s\) · (\d+) probable\(s\)$/, '$1 proven · $2 probable'], [/^(\d+) point\(s\) d'injection$/, '$1 injection point(s)'],
  [/^Chaîne intègre · (\d+) entrées$/, 'Intact chain · $1 entries'], [/^Chaîne rompue à l'entrée #(\d+) : (.*)$/, 'Chain broken at entry #$1: $2'],
  [/^Plugin v(\S+) · (.+)$/, 'Plugin v$1 · $2'], [/^Plugin v(\S+) · non signé$/, 'Plugin v$1 · unsigned'],
  [/^Signé · (.+)$/, 'Signed · $1'], [/^Signature valide · (.+)$/, 'Valid signature · $1'],
  [/^Mettre à jour \((.+) → (.+)\)$/, 'Update ($1 → $2)'], [/^Verdict : (.+)$/, 'Verdict: $1'],
  [/^Instance auto-hébergée · (.+)$/, 'Self-hosted instance · $1'], [/^Campagne #(\d+)$/, 'Campaign #$1'], [/^campagne #(\d+)$/, 'campaign #$1'],
  [/^Callback (\w+) reçu après ([\d.]+) s$/, '$1 callback received after $2 s'],
  [/^usage unique · expire à (.+)$/, 'single use · expires at $1'], [/^source (.+?)( = IP de l’asset)?$/, 'source $1'],
  [/^(\d+) s sur (\d+) s\. Sans callback, verdict « non concluant »\.$/, '$1 s of $2 s. Without a callback, verdict "inconclusive".'],
  [/^Généré le (.+)\. Après un renouvellement, redéposez le fichier : l'ancien contenu ne prouve plus rien\.$/, 'Generated on $1. After a renewal, plant the file again: the old content no longer proves anything.'],
  [/^Vérifiée le (.+?)(?: · valable jusqu'au (.+))?$/, 'Verified on $1'], [/^Jeton à publier avant le (.+)\.$/, 'Token to publish before $1.'],
  [/^(\d+) canaris? émis$/, '$1 canary issued'], [/^(\d+) \(usage unique\)$/, '$1 (single use)'],
  [/^Mot de passe initial de (.+)$/, 'Initial password of $1'], [/^Nouveau mot de passe de (.+)$/, 'New password of $1'],
  [/^Dépôt : (.+) · éditeur (.+)$/, 'Repository: $1 · publisher $2'], [/^dernière lecture (.+) · (\d+) requête\(s\) depuis$/, 'last read $1 · $2 request(s) from'],
  [/^Rôle de (.+)$/, 'Role of $1'], [/^Supprimer (.+) et son historique de checks \?$/, 'Delete $1 and its check history?'],
  [/^(\S+) · dernière lecture (.+)$/, '$1 · last read $2'],
]

function translate(s: string): string | null {
  const core = s.replace(/\s+/g, ' ').trim()
  if (!core) return null
  const hit = dict[core]
  if (hit !== undefined) return s.replace(s.trim(), hit)
  for (const [re, rep] of patterns) {
    if (re.test(core)) return s.replace(s.trim(), core.replace(re, rep))
  }
  return null
}

const SKIP = 'pre, code, textarea, script, style, .mono, [data-no-i18n]'
const ATTRS = ['placeholder', 'title', 'aria-label', 'alt']

function translateNode(n: Node) {
  if (n.nodeType === Node.TEXT_NODE) {
    const p = n.parentElement
    if (!p || p.closest(SKIP)) return
    const t = translate(n.nodeValue ?? '')
    if (t !== null && t !== n.nodeValue) n.nodeValue = t
    return
  }
  if (n.nodeType !== Node.ELEMENT_NODE) return
  const el = n as Element
  if (el.closest(SKIP)) return
  for (const a of ATTRS) {
    const v = el.getAttribute(a)
    if (v) {
      const t = translate(v)
      if (t !== null && t !== v) el.setAttribute(a, t)
    }
  }
  el.childNodes.forEach(translateNode)
}

/** Démarre la traduction automatique de l'interface si la langue est l'anglais. */
export function startI18n(root: HTMLElement) {
  const lang = getLang()
  document.documentElement.lang = lang
  if (lang !== 'en') return
  translateNode(root)
  new MutationObserver((records) => {
    for (const r of records) {
      if (r.type === 'characterData') translateNode(r.target)
      else if (r.type === 'attributes') translateNode(r.target)
      else r.addedNodes.forEach(translateNode)
    }
  }).observe(root, { subtree: true, childList: true, characterData: true, attributes: true, attributeFilter: ATTRS })
}

export const _test = { translate }
