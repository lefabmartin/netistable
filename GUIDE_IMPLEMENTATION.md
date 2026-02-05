# Guide Complet d'Implémentation - Système Anti-Bot Avancé

## 📋 Table des Matières

1. [Architecture Globale](#architecture-globale)
2. [Structure du Projet](#structure-du-projet)
3. [Panel d'Administration](#panel-dadministration)
4. [Fonctionnalités Anti-Bot](#fonctionnalités-anti-bot)
5. [Intégration et Configuration](#intégration-et-configuration)
6. [Déploiement](#déploiement)

---

## 🏗️ Architecture Globale

### Vue d'ensemble

Le système est une **plateforme de protection multi-couches** contre les bots, scanners et accès non autorisés. Il combine :

- **Détection proactive** : Identification des bots avant qu'ils n'accèdent au contenu
- **Filtrage géographique** : Restriction par pays
- **Gestion des listes** : Blacklist/Whitelist dynamiques
- **Analyse comportementale** : Détection basée sur le comportement utilisateur
- **Captcha adaptatif** : hCaptcha selon le niveau de confiance
- **Monitoring** : Logs et statistiques en temps réel

### Architecture en Couches

```
┌─────────────────────────────────────────────────────────┐
│                    COUCHE PRÉSENTATION                  │
│  index.php | do.php | Pages protégées                  │
└─────────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────────┐
│              COUCHE DE SÉCURITÉ (Priorité)              │
│  0. Scanner UA (0.1ms)                                  │
│  1. Datacenter Detection                                │
│  2. Blacklist/Whitelist                                 │
│  3. Geo-filter                                          │
└─────────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────────┐
│            COUCHE D'ANALYSE ANTI-BOT                    │
│  - User-Agent Analysis                                 │
│  - Headers Check                                        │
│  - Timing Analysis                                      │
│  - Fingerprint Browser                                  │
│  - Behavior Analysis                                    │
│  - Honeypot Detection                                   │
│  - Proxy/Tor/VPN Detection                             │
└─────────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────────┐
│              COUCHE DE VALIDATION                      │
│  - Score Calculation (0-100)                           │
│  - hCaptcha Adaptatif                                   │
│  - Proof of Work (si nécessaire)                       │
└─────────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────────┐
│              COUCHE DE LOGGING                         │
│  - BotFuckLogger                                        │
│  - Logs spécialisés                                    │
│  - Statistiques                                         │
└─────────────────────────────────────────────────────────┘
```

### Flux de Traitement Principal

```
Requête entrante
    ↓
Rate Limiting (30 req/min, 200 req/h)
    ↓
Scanner UA Check (blocage immédiat si détecté)
    ↓
Datacenter Detection (blocage si datacenter)
    ↓
Blacklist Check (blocage si présent)
    ↓
Whitelist Check (autorisation si présent)
    ↓
Geo-filter (blocage si pays non autorisé)
    ↓
Analyse Anti-Bot Complète
    ├─ User-Agent
    ├─ Headers
    ├─ Timing
    ├─ Cookie JS
    ├─ Honeypot
    ├─ Datacenter
    ├─ Proxy/Tor/VPN
    ├─ Comportement
    ├─ Fingerprint
    └─ JS Challenge
    ↓
Calcul Score (0-100)
    ↓
Décision:
    ├─ Score >= 70 → Accès direct
    ├─ Score 40-69 → hCaptcha invisible
    ├─ Score < 40 → hCaptcha visible
    └─ Score < 50 OU flags critiques → Blocage
    ↓
Logging & Statistiques
```

---

## 📁 Structure du Projet

### Arborescence Complète

```
projet/
├── index.php                          # Point d'entrée principal
├── do.php                             # Point d'entrée alternatif
├── bot-trap.php                       # Piège pour bots
├── blacklist.txt                      # Liste des IPs bloquées
├── whitelist.txt                      # Liste des IPs autorisées
├── botfuck.txt                       # Logs centralisés
├── robots.txt                         # Exclusion robots
│
├── k7m9x2p/                           # Dossier sécurisé
│   ├── config/
│   │   └── config.php                 # Configuration Telegram & hCaptcha
│   │
│   ├── panel/                         # Modules de sécurité
│   │   ├── ozyadmin.php              # Panel d'administration
│   │   │
│   │   ├── Détection & Analyse
│   │   │   ├── bot_detection.php     # Système anti-bot principal
│   │   │   ├── datacenter_detection.php
│   │   │   ├── proxy_detection.php
│   │   │   ├── fingerprint.php
│   │   │   ├── behavior_analysis.php
│   │   │   ├── mouse_dynamics.php
│   │   │   ├── webgl_fingerprint.php
│   │   │   ├── honeypot.php
│   │   │   └── js_challenge.php
│   │   │
│   │   ├── Gestion
│   │   │   ├── ip_manager.php        # Gestion blacklist/whitelist
│   │   │   ├── geo_filter.php       # Filtrage géographique
│   │   │   ├── rate_limiter.php      # Limitation de débit
│   │   │   └── visitor_manager.php
│   │   │
│   │   ├── Validation
│   │   │   ├── hcaptcha.php         # hCaptcha adaptatif
│   │   │   └── proof_of_work.php    # Proof of Work
│   │   │
│   │   ├── Logging
│   │   │   └── botfuck_logger.php   # Logger centralisé
│   │   │
│   │   ├── Configuration
│   │   │   ├── bot_detection_config.json
│   │   │   └── allowed_countries.json
│   │   │
│   │   └── Logs & Cache
│   │       ├── bot_logs.txt
│   │       ├── datacenter_logs.txt
│   │       ├── datacenter_cache.json
│   │       ├── proxy_logs.txt
│   │       ├── proxy_cache.json
│   │       ├── rate_limiter_data.json
│   │       └── hcaptcha_stats.json
│   │
│   └── r4t8w1n/                       # Pages protégées
│       ├── ip_check.php              # Vérification IP
│       └── [pages protégées]
│
└── [autres fichiers]
```

### Fichiers Clés

#### Points d'Entrée

- **`index.php`** : Point d'entrée principal avec toutes les vérifications
- **`do.php`** : Point d'entrée alternatif avec vérifications simplifiées
- **`bot-trap.php`** : Piège pour bots accédant directement

#### Configuration

- **`k7m9x2p/config/config.php`** : Configuration Telegram et hCaptcha
- **`k7m9x2p/panel/bot_detection_config.json`** : Configuration anti-bot
- **`k7m9x2p/panel/allowed_countries.json`** : Liste des pays autorisés

#### Listes

- **`blacklist.txt`** : IPs bloquées (format: `IP # commentaire`)
- **`whitelist.txt`** : IPs autorisées (format: `IP`)

#### Logs

- **`botfuck.txt`** : Logs centralisés de tous les blocages
- **`k7m9x2p/panel/bot_logs.txt`** : Logs détaillés anti-bot
- **`k7m9x2p/panel/datacenter_logs.txt`** : Logs datacenter
- **`k7m9x2p/panel/proxy_logs.txt`** : Logs proxy/Tor/VPN

---

## 🎛️ Panel d'Administration

### Accès au Panel

**URL :** `https://votre-domaine.com/k7m9x2p/panel/ozyadmin.php`

**Mot de passe :** Défini dans `ozyadmin.php` (ligne 21)
```php
$adminPassword = 'music2018'; // À modifier
```

### Sections du Panel

#### 1. Dashboard

**Onglet :** `?tab=dashboard`

**Fonctionnalités :**
- Vue d'ensemble des statistiques
- Nombre de bots bloqués aujourd'hui
- Top pays bloqués
- Top IPs bloquées
- Graphiques de tendances

#### 2. Configuration Telegram

**Onglet :** `?tab=telegram`

**Fonctionnalités :**
- Configuration du bot Telegram
- Ajout/suppression de chat IDs
- Test de connexion
- Notifications automatiques

**Configuration :**
```php
// Dans config.php
$bot = 'VOTRE_BOT_TOKEN';
$chat_ids = array('CHAT_ID_1', 'CHAT_ID_2');
```

#### 3. Filtrage Géographique

**Onglet :** `?tab=geo`

**Fonctionnalités :**
- Ajouter un pays autorisé
- Retirer un pays
- Définir la liste complète
- Voir les pays actuellement autorisés

**Format :** Codes pays ISO 2 lettres (ex: `FR`, `US`, `GB`)

#### 4. Configuration Anti-Bot

**Onglet :** `?tab=antibot`

**Sections :**

##### Vérifications Actives
- ✅ User-Agent Check
- ✅ Header Check
- ✅ Timing Check
- ✅ JS Cookie Check
- ✅ Fingerprint Check
- ✅ Behavior Check
- ✅ JS Challenge Check
- ✅ Honeypot Check
- ✅ Datacenter Check
- ✅ Proxy Check
- ✅ Tor Check
- ✅ VPN Check
- ✅ hCaptcha Check

##### Actions de Blocage
- 🛡️ Bloquer Datacenter
- 🛡️ Bloquer Datacenter (même pays autorisés)
- 🛡️ Bloquer Proxy
- 🛡️ Bloquer Tor
- 🛡️ Bloquer VPN

##### Seuils
- Score comportement minimum : 50
- Score fingerprint minimum : 50

#### 5. Gestion des Listes IP

**Onglet :** `?tab=iplists`

**Fonctionnalités :**

##### Blacklist
- Ajouter une IP avec raison
- Retirer une IP
- Voir toutes les IPs blacklistées
- Rechercher une IP

##### Whitelist
- Ajouter une IP
- Retirer une IP
- Voir toutes les IPs whitelistées
- Rechercher une IP

#### 6. Analyse d'IP

**Onglet :** `?tab=analyze`

**Fonctionnalités :**
- Analyser une IP spécifique
- Voir les informations complètes :
  - Pays, région, ville
  - ISP, Organisation
  - ASN
  - Statut datacenter
  - Statut proxy/Tor/VPN
  - Présence dans blacklist/whitelist
  - Autorisation géographique

#### 7. Logs

**Onglet :** `?tab=logs`

**Sections :**
- Logs BotFuck (tous les blocages)
- Logs Datacenter
- Logs Proxy
- Statistiques par raison
- Statistiques par pays
- Statistiques par IP

#### 8. Configuration hCaptcha

**Onglet :** `?tab=hcaptcha`

**Fonctionnalités :**
- Site Key
- Secret Key
- Seuil de score (threshold)
- Statistiques de vérification

---

## 🛡️ Fonctionnalités Anti-Bot

### 1. Détection User-Agent

**Fichier :** `bot_detection.php`

**Méthode :** `BotDetection::isKnownScanner()`

**Patterns détectés :**
- **Scanners de sécurité** : Censys, Shodan, Nmap, Nuclei, etc. (40+)
- **Bots génériques** : bot, crawler, spider, scraper, etc. (30+)
- **Outils** : curl, wget, python, java, selenium, etc.

**Performance :** ~0.1ms (vérification locale)

**Action :** Blocage immédiat + blacklist

### 2. Détection Datacenter

**Fichier :** `datacenter_detection.php`

**Méthodes :**
1. Flag `hosting` de l'API
2. Flag `proxy` de l'API
3. Liste d'organisations (60+)
4. Liste d'ASN (30+)

**APIs utilisées :**
- Principale : `ip-api.com`
- Alternative : `ipapi.co`

**Cache :** 24h pour IPs normales, 1h pour datacenters

### 3. Détection Proxy/Tor/VPN

**Fichier :** `proxy_detection.php`

**Types détectés :**
- Proxy
- Tor
- VPN

**Méthodes :**
- Vérification des headers HTTP
- Liste d'IPs Tor connues
- Détection via API
- Analyse de l'organisation

### 4. Analyse des Headers HTTP

**Méthode :** `BotDetection::checkHeaders()`

**Headers requis :**
- `HTTP_ACCEPT`
- `HTTP_ACCEPT_LANGUAGE`
- `HTTP_ACCEPT_ENCODING`

**Détection :** Si 2+ headers manquants → Suspicion

### 5. Analyse du Timing

**Méthode :** `BotDetection::checkTiming()`

**Détection :** Requêtes trop rapides (< 0.5 secondes)

**Protection :** Délai aléatoire ajouté (500-2000ms)

### 6. Vérification Cookie JavaScript

**Méthode :** `BotDetection::checkJSCookie()`

**Détection :** Absence du cookie `js_enabled`

**Note :** Ne bloque pas directement, réduit le score

### 7. Détection Honeypot

**Fichier :** `honeypot.php`

**Principe :** Champs cachés que seuls les bots remplissent

**Champs :** `website_url`, `user_homepage`, `contact_website`, etc.

**Techniques :** Position absolue, opacité 0, display none

### 8. Fingerprint Navigateur

**Fichier :** `fingerprint.php`

**Critères analysés :**
- User-Agent
- Headers HTTP
- Résolution écran
- Timezone
- Langues
- Plugins
- Canvas fingerprint
- WebGL fingerprint
- Fonts disponibles

**Score :** 0-100 (plus élevé = plus légitime)

### 9. Analyse Comportementale

**Fichier :** `behavior_analysis.php`

**Critères analysés :**
- Mouvements de souris
- Vitesse de frappe
- Patterns de navigation
- Temps de réponse
- Interactions utilisateur

**Score :** 0-100

### 10. Mouse Dynamics

**Fichier :** `mouse_dynamics.php`

**Analyse :**
- Trajectoire de la souris
- Vitesse des mouvements
- Accélération
- Patterns humains vs bots

### 11. WebGL Fingerprint

**Fichier :** `webgl_fingerprint.php`

**Analyse :** Empreinte unique du GPU et du navigateur

### 12. Challenge JavaScript

**Fichier :** `js_challenge.php`

**Principe :** Vérification que JavaScript est exécuté

### 13. hCaptcha Adaptatif

**Fichier :** `hcaptcha.php`

**Modes selon le score :**
- **Score >= 70** : Pas de captcha
- **Score 40-69** : hCaptcha invisible
- **Score < 40** : hCaptcha visible

**Configuration :**
```php
$hcaptcha_site_key = 'VOTRE_SITE_KEY';
$hcaptcha_secret_key = 'VOTRE_SECRET_KEY';
$hcaptcha_threshold = 70; // Seuil pour éviter le captcha
```

### 14. Proof of Work

**Fichier :** `proof_of_work.php`

**Principe :** Calcul cryptographique pour ralentir les bots

**Utilisation :** Si score très faible (< 30)

### 15. Rate Limiting

**Fichier :** `rate_limiter.php`

**Limites :**
- 30 requêtes/minute
- 200 requêtes/heure

**Blocage progressif :**
- 1ère infraction : 1 minute
- 2ème infraction : 5 minutes
- 3ème infraction : 15 minutes
- 4ème+ infraction : 1 heure

### 16. Filtrage Géographique

**Fichier :** `geo_filter.php`

**Fonctionnalités :**
- Liste de pays autorisés
- Blocage automatique des autres pays
- Gestion via panel admin

**APIs utilisées :**
- `ip-api.com`
- `ipapi.co`
- `ipinfo.io` (fallback)

### 17. Gestion Blacklist/Whitelist

**Fichier :** `ip_manager.php`

**Fonctionnalités :**
- Ajout/suppression d'IPs
- Recherche
- Commentaires pour blacklist
- Migration whitelist → blacklist

### 18. Logging Centralisé

**Fichier :** `botfuck_logger.php`

**Fonctionnalités :**
- Logs structurés
- Statistiques
- Parsing des logs
- Export

---

## ⚙️ Intégration et Configuration

### Configuration Initiale

#### 1. Configuration Telegram

**Fichier :** `k7m9x2p/config/config.php`

```php
<?php
// Configuration Telegram Bot
$bot = 'VOTRE_BOT_TOKEN';
$chat_ids = array('CHAT_ID_1', 'CHAT_ID_2');

// Configuration hCaptcha
$hcaptcha_site_key = 'VOTRE_SITE_KEY';
$hcaptcha_secret_key = 'VOTRE_SECRET_KEY';
$hcaptcha_threshold = 70;
```

**Obtenir un Bot Token :**
1. Créer un bot via @BotFather sur Telegram
2. Copier le token fourni

**Obtenir un Chat ID :**
1. Envoyer un message à votre bot
2. Visiter : `https://api.telegram.org/bot<VOTRE_TOKEN>/getUpdates`
3. Trouver `chat.id` dans la réponse

#### 2. Configuration Anti-Bot

**Fichier :** `k7m9x2p/panel/bot_detection_config.json`

```json
{
    "enabled": true,
    "user_agent_check": true,
    "header_check": true,
    "timing_check": true,
    "js_cookie_check": true,
    "fingerprint_check": true,
    "behavior_check": true,
    "js_challenge_check": true,
    "honeypot_check": true,
    "datacenter_check": true,
    "proxy_check": true,
    "tor_check": true,
    "vpn_check": true,
    "hcaptcha_check": true,
    "min_behavior_score": 50,
    "min_fingerprint_score": 50,
    "block_datacenter": true,
    "block_datacenter_all_countries": true,
    "block_proxy": true,
    "block_tor": true,
    "block_vpn": true
}
```

#### 3. Configuration Géographique

**Fichier :** `k7m9x2p/panel/allowed_countries.json`

```json
["CM", "MA", "BM", "US", "GB", "HK"]
```

**Codes pays ISO 2 lettres**

### Intégration dans index.php

Le point d'entrée principal charge tous les modules :

```php
<?php
session_start();

// Headers anti-bot
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header('X-XSS-Protection: 1; mode=block');

// Charger les modules
require_once(__DIR__ . "/secure/panel/ip_manager.php");
require_once(__DIR__ . "/secure/panel/bot_detection.php");
require_once(__DIR__ . "/secure/panel/geo_filter.php");
require_once(__DIR__ . "/secure/panel/hcaptcha.php");
require_once(__DIR__ . "/secure/panel/rate_limiter.php");
require_once(__DIR__ . "/secure/panel/botfuck_logger.php");
require_once(__DIR__ . "/secure/panel/proof_of_work.php");
require_once(__DIR__ . "/secure/panel/mouse_dynamics.php");
require_once(__DIR__ . "/secure/panel/webgl_fingerprint.php");
include(__DIR__ . "/secure/config/config.php");

// Initialiser
$ipManager = new IPManager();
$ip = $ipManager->getClientIp();
$geoFilter = new GeoFilter();

// Rate Limiting
if (RateLimiter::isBlocked($ip)) {
    header("HTTP/1.1 429 Too Many Requests");
    exit("Too many requests.");
}
RateLimiter::increment($ip);

// Vérifications de sécurité...
// (voir section Architecture pour le flux complet)
```

### Personnalisation

#### Ajouter une Organisation Datacenter

```php
DatacenterDetection::addOrganization('nouveau-hébergeur');
```

#### Ajouter un ASN Datacenter

```php
DatacenterDetection::addASN('AS99999');
```

#### Modifier les Patterns de Bots

Éditer le tableau `$botPatterns` dans `bot_detection.php`

#### Modifier les Limites de Rate Limiting

Éditer les constantes dans `rate_limiter.php` :
```php
const LIMIT_PER_MINUTE = 30;
const LIMIT_PER_HOUR = 200;
```

---

## 🚀 Déploiement

### Prérequis

- PHP 7.0+
- Extensions : `json`, `session`, `curl` (recommandé)
- Accès réseau pour les APIs externes
- Permissions d'écriture pour les fichiers de logs et cache

### Installation

1. **Copier les fichiers**
   ```bash
   cp -r k7m9x2p/ /chemin/vers/votre/projet/
   ```

2. **Configurer les permissions**
   ```bash
   chmod 755 k7m9x2p/panel/
   chmod 644 k7m9x2p/panel/*.json
   chmod 666 k7m9x2p/panel/*.txt
   chmod 666 blacklist.txt whitelist.txt botfuck.txt
   ```

3. **Configurer Telegram**
   - Éditer `k7m9x2p/config/config.php`
   - Ajouter votre bot token et chat IDs

4. **Configurer hCaptcha**
   - Obtenir les clés sur https://www.hcaptcha.com/
   - Ajouter dans `config.php`

5. **Configurer les pays autorisés**
   - Via le panel admin ou directement dans `allowed_countries.json`

6. **Tester**
   - Accéder au panel admin
   - Vérifier les logs
   - Tester avec différentes IPs

### Sécurité

#### Protection du Panel Admin

1. **Changer le mot de passe**
   ```php
   $adminPassword = 'VOTRE_MOT_DE_PASSE_FORT';
   ```

2. **Restreindre l'accès par IP** (optionnel)
   ```php
   $allowedIPs = ['VOTRE_IP'];
   if (!in_array($_SERVER['REMOTE_ADDR'], $allowedIPs)) {
       die('Access denied');
   }
   ```

3. **Utiliser HTTPS**
   - Obligatoire pour la sécurité

4. **Protéger les fichiers de config**
   - Ne pas exposer `config.php` publiquement
   - Utiliser `.htaccess` si Apache

### Monitoring

#### Vérifier les Logs

```bash
# Logs centralisés
tail -f botfuck.txt

# Logs datacenter
tail -f k7m9x2p/panel/datacenter_logs.txt

# Logs proxy
tail -f k7m9x2p/panel/proxy_logs.txt
```

#### Statistiques

Accéder au panel admin → Onglet "Logs" pour voir les statistiques

### Maintenance

#### Nettoyer les Caches

```php
DatacenterDetection::clearCache();
ProxyDetection::clearCache();
```

#### Vider les Logs

Via le panel admin ou manuellement :
```bash
> botfuck.txt
> k7m9x2p/panel/bot_logs.txt
```

#### Mettre à Jour les Listes

- Organisations datacenter : Éditer `datacenter_detection.php`
- Patterns bots : Éditer `bot_detection.php`
- ASN : Éditer `datacenter_detection.php`

---

## 📊 Exemples d'Utilisation

### Exemple 1 : Vérifier une IP

```php
require_once 'k7m9x2p/panel/datacenter_detection.php';
require_once 'k7m9x2p/panel/proxy_detection.php';

$ip = '121.127.43.194';

// Vérifier datacenter
$dcResult = DatacenterDetection::isDatacenterIP($ip);
if ($dcResult['isDatacenter']) {
    echo "Datacenter détecté: " . $dcResult['reason'];
}

// Vérifier proxy
$proxyResult = ProxyDetection::checkAll($ip);
if ($proxyResult['isProxy']) {
    echo "Proxy détecté";
}
```

### Exemple 2 : Ajouter une IP à la Blacklist

```php
require_once 'k7m9x2p/panel/ip_manager.php';

$ipManager = new IPManager();
$ipManager->addToBlacklist('192.168.1.100', 'Raison du blocage');
```

### Exemple 3 : Vérifier un Pays

```php
require_once 'k7m9x2p/panel/geo_filter.php';

$geoFilter = new GeoFilter();
if ($geoFilter->isAllowed('192.168.1.100')) {
    echo "Pays autorisé";
} else {
    echo "Pays non autorisé";
}
```

### Exemple 4 : Analyser un Visiteur

```php
require_once 'k7m9x2p/panel/bot_detection.php';

$results = BotDetection::analyzeAll();
$score = $results['overall']['score'];

if ($score >= 70) {
    echo "Visiteur légitime";
} elseif ($score < 50) {
    echo "Bot probable";
}
```

---

## 🔧 Dépannage

### Problèmes Courants

#### 1. Les APIs ne répondent pas

**Solution :** Vérifier la connectivité réseau et les timeouts

#### 2. Les logs ne s'écrivent pas

**Solution :** Vérifier les permissions d'écriture

#### 3. Le panel admin ne fonctionne pas

**Solution :** Vérifier le mot de passe et les sessions PHP

#### 4. Les notifications Telegram ne partent pas

**Solution :** Vérifier le bot token et les chat IDs

#### 5. Le captcha ne s'affiche pas

**Solution :** Vérifier les clés hCaptcha dans `config.php`

---

## 📚 Références

### APIs Externes

- **ip-api.com** : https://ip-api.com/docs
- **ipapi.co** : https://ipapi.co/documentation
- **hCaptcha** : https://www.hcaptcha.com/
- **Telegram Bot API** : https://core.telegram.org/bots/api

### Documentation

- **ASN Database** : https://www.iana.org/assignments/as-numbers/
- **Codes Pays ISO** : https://www.iso.org/iso-3166-country-codes.html

---

**Version :** 1.0  
**Date :** 2024  
**Auteur :** Guide d'implémentation complet
