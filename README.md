# IAM – création de comptes Active Directory

Service qui crée les comptes utilisateurs dans Active Directory à partir de quatre données :
**nom, prénom, adresse mail, matricule**. Il génère lui-même le **login** et le **mot de passe
initial**. Il s'utilise par une **API REST** (pour vos autres logiciels) ou par un petit
formulaire web.

## Ce que fait une création

| Donnée | Règle | Attribut AD |
| --- | --- | --- |
| Nom, prénom | fournis | `sn`, `givenName`, `displayName`, `cn` |
| Mail | fourni, unique dans le domaine | `mail` |
| Matricule | fourni, unique dans le domaine | `employeeID` |
| Login | 3 premières lettres du prénom + 3 premières lettres du nom | `sAMAccountName`, `userPrincipalName` |
| Mot de passe | 10 caractères, généré | `unicodePwd` |

**Login.** `Marie Dupont` → `mardup`. Les accents, espaces, tirets et apostrophes sont ignorés
(`Éloïse D'Hondt` → `elodho`), un nom de moins de 3 lettres est pris en entier (`Li Wu` → `liwu`).
Si le login existe déjà, un numéro est ajouté : `mardup2`, `mardup3`… Le login n'est jamais
choisi par l'appelant.

**Mot de passe.** Tiré par le générateur cryptographique du système, avec au moins une
majuscule, une minuscule, un chiffre et un symbole, sans caractère ambigu (`O`/`0`, `I`/`l`/`1`)
et sans fragment du nom, du prénom ou du login (règle de complexité d'Active Directory).
Il est renvoyé **une seule fois** dans la réponse, n'est ni conservé ni journalisé, et le compte
est créé avec l'obligation de **le changer à la première ouverture de session**.

> Les recommandations actuelles (NIST SP 800-63B, ANSSI) privilégient la longueur à la
> complexité. Dix caractères conviennent pour un mot de passe initial à usage unique ; la
> longueur est réglable avec `IAM_PASSWORD_LENGTH` (10 au minimum), et la politique de mots de
> passe du domaine reste celle qui s'applique au mot de passe choisi ensuite par la personne.

## Essayer sans Active Directory

Le mode démonstration garde les comptes en mémoire : rien n'est écrit dans l'annuaire.

```bash
uv sync
uv run iam-ad generate-api-key logiciel-rh      # affiche la clé et son empreinte
export IAM_AUTH_MODE=api_key
export IAM_API_KEYS='{"logiciel-rh": "<empreinte affichée>"}'
export IAM_DIRECTORY_BACKEND=memory
uv run iam-ad serve                             # http://127.0.0.1:8443
```

Le formulaire est sur `http://127.0.0.1:8443/`, l'API sur `/api/v1/users`.

## API

```bash
curl -X POST https://iam.exemple.be/api/v1/users \
  -H "Authorization: Bearer $JETON" \
  -H "Content-Type: application/json" \
  -d '{"nom": "Dupont", "prenom": "Marie", "mail": "marie.dupont@exemple.be", "matricule": "M004217"}'
```

Réponse `201` :

```json
{
  "login": "mardup",
  "upn": "mardup@exemple.be",
  "dn": "CN=Marie Dupont,OU=Utilisateurs,DC=corp,DC=exemple,DC=be",
  "nom": "Dupont",
  "prenom": "Marie",
  "nom_affiche": "Marie Dupont",
  "mail": "marie.dupont@exemple.be",
  "matricule": "M004217",
  "mot_de_passe_temporaire": "…",
  "changement_mot_de_passe_requis": true
}
```

Les erreurs ont toutes la forme `{"code": "...", "detail": "..."}` :

| HTTP | `code` | Signification |
| --- | --- | --- |
| 401 | `non_authentifie` | jeton ou clé absent, invalide ou expiré |
| 403 | `acces_refuse` | jeton valide mais sans le rôle requis |
| 409 | `matricule_deja_utilise`, `mail_deja_utilise`, `login_indisponible`, `creation_concurrente` | doublon |
| 422 | `donnees_invalides` (avec le détail par champ dans `erreurs`), `matricule_invalide`, `domaine_mail_refuse`, `login_non_derivable` | données refusées |
| 502 | `operation_refusee`, `erreur_annuaire` | l'annuaire a refusé ; aucun compte n'est laissé |
| 503 | `annuaire_indisponible` | annuaire injoignable |

Le contrat OpenAPI complet est servi sur `/openapi.json`. Sondes : `/healthz` et `/readyz`.

## Authentification des appelants

Le jeton se présente dans l'en-tête `Authorization: Bearer …`.

- **`IAM_AUTH_MODE=oidc`** (recommandé) : jeton d'accès JWT émis par votre fournisseur
  d'identité (Entra ID, AD FS, Keycloak…). La signature, l'émetteur, l'audience et l'expiration
  sont vérifiés, et le jeton doit porter le rôle `IAM_OIDC_REQUIRED_ROLE`
  (`iam.users.create` par défaut). Chaque logiciel client obtient son jeton par le flux
  *client credentials* ; aucun secret partagé n'est stocké ici.
- **`IAM_AUTH_MODE=api_key`** : une clé aléatoire de 256 bits par logiciel client, générée par
  `iam-ad generate-api-key <nom>`. Seule l'empreinte SHA-256 figure dans la configuration.

## Préparer Active Directory

1. **LDAPS** doit être actif sur les contrôleurs de domaine (port 636) : Active Directory
   n'accepte l'écriture d'un mot de passe que sur un canal chiffré. Fournissez le certificat de
   votre autorité interne dans `IAM_AD_CA_CERT_FILE` et désignez les contrôleurs par leur
   **nom DNS**, tel qu'il figure dans leur certificat (une adresse IP est refusée).
2. **Compte de service dédié**, sans appartenance à un groupe d'administration. Sur l'unité
   d'organisation cible uniquement (`IAM_AD_USERS_OU`), déléguez-lui : créer et supprimer des
   objets utilisateur, écrire leurs propriétés, réinitialiser leur mot de passe. La suppression
   sert à annuler une création qui échoue en cours de route.
3. La **politique de mots de passe du domaine** doit accepter la longueur configurée ; sinon la
   création est refusée proprement (`502 operation_refusee`). Augmentez alors
   `IAM_PASSWORD_LENGTH`.

## Configuration

Toutes les variables sont décrites dans [`.env.example`](.env.example). Le mot de passe du compte
de service peut être fourni par fichier secret (`/run/secrets/iam_ad_bind_password`) plutôt que
par variable d'environnement.

## Déploiement

```bash
cp .env.example .env            # puis adapter
mkdir secrets                   # ca.pem et ad_bind_password.txt
docker compose up -d --build
```

Le conteneur tourne sans privilèges, en lecture seule, et écoute en HTTP sur `127.0.0.1:8443` :
placez devant lui un reverse proxy qui assure le TLS. Sans proxy, `iam-ad serve --tls-cert …
--tls-key …` sert directement en HTTPS.

## Mesures de sécurité

- LDAPS obligatoire, TLS 1.2 minimum, certificat et nom du contrôleur de domaine vérifiés.
- Compte créé désactivé, activé seulement une fois le mot de passe posé ; annulation complète
  si une étape échoue.
- Valeurs échappées dans les filtres de recherche et les noms distinctifs (pas d'injection LDAP).
- Entrées validées strictement ; champs inconnus refusés.
- Jetons JWT : algorithmes asymétriques uniquement, `exp`/`iss`/`aud`/`sub` exigés.
- Journal d'audit JSON sur la sortie standard (qui, quoi, quand, résultat), sans aucun secret.
- En-têtes HTTP de sécurité (CSP stricte, HSTS, `no-store`), interface sans dépendance externe.
- Les messages d'erreur renvoyés ne contiennent aucun détail technique de l'annuaire.

À prévoir côté infrastructure : limitation de débit sur le reverse proxy, restriction réseau de
l'accès au service, collecte du journal d'audit, rotation du mot de passe du compte de service.

## Développement

```bash
uv sync
uv run pytest          # tests
uv run ruff check .    # analyse statique
```

Le connecteur LDAP est testé contre l'annuaire simulé de `ldap3` (schéma Active Directory) et la
vérification TLS par de vraies poignées de main sur un serveur local. **Il n'a pas encore été
exécuté contre un Active Directory réel** : validez-le d'abord sur un domaine de test.

## Organisation du code

| Fichier | Rôle |
| --- | --- |
| `src/iam_ad/login.py`, `password.py` | règles de génération du login et du mot de passe |
| `src/iam_ad/service.py` | déroulé d'une création, contrôles d'unicité |
| `src/iam_ad/directory/ldap_ad.py` | connecteur Active Directory (LDAPS) |
| `src/iam_ad/directory/memory.py` | annuaire de démonstration |
| `src/iam_ad/auth.py` | authentification OIDC et clés d'API |
| `src/iam_ad/api.py` | routes HTTP, erreurs, en-têtes de sécurité |
| `src/iam_ad/static/` | formulaire web |
