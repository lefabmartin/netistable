/**
 * Bot Detection Service
 * Détection avancée des bots, scanners et outils automatisés
 */

class BotDetection {
  constructor() {
    // Patterns de User-Agent suspects (40+ scanners de sécurité)
    this.knownScanners = [
      // Scanners de sécurité
      'censys', 'shodan', 'nmap', 'nuclei', 'masscan', 'zmap', 'zgrab',
      'nikto', 'sqlmap', 'wpscan', 'dirbuster', 'gobuster', 'ffuf',
      'burp', 'owasp', 'acunetix', 'nessus', 'qualys', 'openvas',
      'metasploit', 'hydra', 'medusa', 'netcat', 'ncat',
      'arachni', 'skipfish', 'w3af', 'vega', 'zap', 'appscan',
      'webinspect', 'netsparker', 'rapid7', 'tenable', 'nexpose',
      'veracode', 'checkmarx', 'fortify', 'snyk', 'whitesource',
      'blackduck', 'sonarqube', 'semgrep', 'bandit',
      
      // Bots génériques (30+)
      'bot', 'crawler', 'spider', 'scraper', 'harvest', 'extract',
      'grab', 'miner', 'validator', 'checker', 'monitor', 'probe',
      'scan', 'exploit', 'hack', 'attack', 'vulnerability', 'penetration',
      'fuzz', 'brute', 'inject', 'payload', 'malware', 'virus',
      'trojan', 'worm', 'rootkit', 'backdoor', 'keylogger', 'spyware',
      
      // Outils automatisés
      'curl', 'wget', 'python-requests', 'python-urllib', 'java/',
      'perl', 'ruby', 'php/', 'go-http-client', 'node-fetch',
      'axios', 'httpie', 'postman', 'insomnia',
      
      // Automation/Testing
      'selenium', 'webdriver', 'phantomjs', 'headless', 'puppeteer',
      'playwright', 'cypress', 'testcafe', 'nightwatch', 'protractor',
      'karma', 'jasmine', 'mocha', 'jest', 'qunit',
      'headlesschrome', 'headlessfirefox', 'chromedriver',
      
      // Moteurs de recherche (optionnel - à activer si besoin)
      'googlebot', 'bingbot', 'slurp', 'duckduckbot', 'baiduspider',
      'yandexbot', 'sogou', 'exabot', 'facebot', 'ia_archiver',
      'msnbot', 'ahrefs', 'semrush', 'mj12bot', 'dotbot', 'petalbot',
      
      // Outils de monitoring
      'uptimerobot', 'pingdom', 'gtmetrix', 'pagespeed', 'lighthouse',
      'sitechecker', 'seositecheckup', 'seomator', 'serpstat'
    ];

    // Headers HTTP requis pour un navigateur légitime
    this.requiredHeaders = [
      'accept',
      'accept-language',
      'accept-encoding'
    ];

    // Headers suspects qui indiquent un proxy/bot
    this.suspiciousHeaders = [
      'x-forwarded-for',
      'via',
      'forwarded',
      'x-real-ip',
      'x-proxy-id',
      'proxy-connection'
    ];

    // Stockage des timestamps pour rate limiting
    this.requestTimestamps = new Map();
    
    // Stockage des infractions pour blocage progressif
    this.infractions = new Map();

    console.log('[BotDetection] 🛡️ Service initialized with', this.knownScanners.length, 'scanner patterns');
  }

  /**
   * Vérifie si le User-Agent correspond à un scanner connu
   * @param {string} userAgent - Le User-Agent à vérifier
   * @returns {object} - { isBot: boolean, reason: string, pattern: string }
   */
  isKnownScanner(userAgent) {
    if (!userAgent) {
      return { isBot: true, reason: 'empty_user_agent', pattern: null };
    }

    const ua = userAgent.toLowerCase();
    
    // Vérifier les User-Agents vides ou suspects
    if (ua === '-' || ua === '' || ua.length < 10) {
      return { isBot: true, reason: 'suspicious_user_agent', pattern: ua };
    }

    // Vérifier contre les patterns connus
    for (const pattern of this.knownScanners) {
      if (ua.includes(pattern)) {
        return { isBot: true, reason: 'known_scanner', pattern };
      }
    }

    return { isBot: false, reason: null, pattern: null };
  }

  /**
   * Analyse les headers HTTP pour détecter les bots
   * @param {object} headers - Les headers de la requête
   * @returns {object} - { score: number, missing: string[], suspicious: string[] }
   */
  checkHeaders(headers) {
    const missing = [];
    const suspicious = [];
    let score = 100;

    // Vérifier les headers requis
    for (const header of this.requiredHeaders) {
      if (!headers[header] && !headers[header.replace('-', '_')]) {
        missing.push(header);
        score -= 15;
      }
    }

    // Vérifier les headers suspects (proxies)
    for (const header of this.suspiciousHeaders) {
      if (headers[header] || headers[header.replace('-', '_')]) {
        suspicious.push(header);
        score -= 5;
      }
    }

    // Bonus pour les headers de navigateur légitimes
    if (headers['sec-ch-ua'] || headers['sec-fetch-mode']) {
      score += 10;
    }

    return {
      score: Math.max(0, Math.min(100, score)),
      missing,
      suspicious,
      isBot: missing.length >= 2
    };
  }

  /**
   * Vérifie le timing des requêtes (détection de bots rapides)
   * @param {string} ip - L'adresse IP du client
   * @returns {object} - { tooFast: boolean, timeSinceLastRequest: number }
   */
  checkTiming(ip) {
    const now = Date.now();
    const lastRequest = this.requestTimestamps.get(ip);
    
    this.requestTimestamps.set(ip, now);

    if (!lastRequest) {
      return { tooFast: false, timeSinceLastRequest: null };
    }

    const timeSinceLastRequest = now - lastRequest;
    
    // Moins de 500ms entre les requêtes = suspect
    return {
      tooFast: timeSinceLastRequest < 500,
      timeSinceLastRequest
    };
  }

  /**
   * Rate limiting - vérifie si l'IP dépasse les limites
   * @param {string} ip - L'adresse IP du client
   * @returns {object} - { blocked: boolean, reason: string, blockDuration: number }
   */
  checkRateLimit(ip, configLimits = null) {
    const now = Date.now();
    const minute = 60 * 1000;
    const hour = 60 * minute;
    const limits = configLimits || {};
    const maxPerMinute = Number.isFinite(Number(limits.requestsPerMinute)) ? Number(limits.requestsPerMinute) : 30;
    const maxPerHour = Number.isFinite(Number(limits.requestsPerHour)) ? Number(limits.requestsPerHour) : 200;
    const blockDurations = Array.isArray(limits.blockDurations) && limits.blockDurations.length >= 4
      ? limits.blockDurations.map(v => Number(v) || 0)
      : [60, 300, 900, 3600];

    // Obtenir ou créer l'historique des requêtes
    if (!this.requestHistory) {
      this.requestHistory = new Map();
    }

    let history = this.requestHistory.get(ip);
    if (!history) {
      history = { requests: [], blocked: false, blockUntil: 0, infractionCount: 0 };
      this.requestHistory.set(ip, history);
    }

    // Vérifier si l'IP est actuellement bloquée
    if (history.blocked && now < history.blockUntil) {
      return {
        blocked: true,
        reason: 'rate_limit_exceeded',
        blockDuration: Math.ceil((history.blockUntil - now) / 1000),
        infractionCount: history.infractionCount
      };
    }

    // Réinitialiser le blocage si expiré
    if (history.blocked && now >= history.blockUntil) {
      history.blocked = false;
    }

    // Ajouter la requête actuelle
    history.requests.push(now);

    // Nettoyer les anciennes requêtes (plus d'une heure)
    history.requests = history.requests.filter(t => now - t < hour);

    // Compter les requêtes par minute et par heure
    const requestsLastMinute = history.requests.filter(t => now - t < minute).length;
    const requestsLastHour = history.requests.length;

    // Limites configurables
    if (requestsLastMinute > maxPerMinute || requestsLastHour > maxPerHour) {
      history.infractionCount++;
      history.blocked = true;

      // Blocage progressif
      let blockDuration;
      switch (history.infractionCount) {
        case 1:
          blockDuration = blockDurations[0] * 1000;
          break;
        case 2:
          blockDuration = blockDurations[1] * 1000;
          break;
        case 3:
          blockDuration = blockDurations[2] * 1000;
          break;
        default:
          blockDuration = blockDurations[3] * 1000;
      }

      history.blockUntil = now + blockDuration;

      return {
        blocked: true,
        reason: requestsLastMinute > maxPerMinute ? 'minute_limit_exceeded' : 'hour_limit_exceeded',
        blockDuration: Math.ceil(blockDuration / 1000),
        infractionCount: history.infractionCount
      };
    }

    return {
      blocked: false,
      requestsLastMinute,
      requestsLastHour
    };
  }

  /**
   * Analyse complète d'une connexion
   * @param {object} req - La requête HTTP/WebSocket
   * @param {string} ip - L'adresse IP du client
   * @returns {object} - Résultat complet de l'analyse
   */
  analyze(req, ip) {
    const userAgent = req.headers['user-agent'] || '';
    const headers = req.headers;

    // 1. Vérification User-Agent
    const scannerCheck = this.isKnownScanner(userAgent);

    // 2. Vérification Headers
    const headerCheck = this.checkHeaders(headers);

    // 3. Vérification Timing
    const timingCheck = this.checkTiming(ip);

    // 4. Rate Limiting
    const rateLimitCheck = this.checkRateLimit(ip);

    // Calcul du score global
    let score = 100;
    const reasons = [];

    if (scannerCheck.isBot) {
      score -= 50;
      reasons.push(`scanner_detected:${scannerCheck.pattern || scannerCheck.reason}`);
    }

    if (headerCheck.isBot) {
      score -= 30;
      reasons.push(`missing_headers:${headerCheck.missing.join(',')}`);
    }

    if (timingCheck.tooFast) {
      score -= 20;
      reasons.push('too_fast_requests');
    }

    if (rateLimitCheck.blocked) {
      score = 0;
      reasons.push(`rate_limited:${rateLimitCheck.reason}`);
    }

    // Ajuster avec le score des headers
    score = Math.min(score, headerCheck.score);

    const result = {
      ip,
      userAgent,
      score: Math.max(0, score),
      isBot: score < 50,
      shouldBlock: scannerCheck.isBot || rateLimitCheck.blocked || score < 30,
      reasons,
      details: {
        scanner: scannerCheck,
        headers: headerCheck,
        timing: timingCheck,
        rateLimit: rateLimitCheck
      }
    };

    console.log(`[BotDetection] 🔍 Analysis for ${ip}: score=${result.score}, isBot=${result.isBot}, reasons=[${reasons.join(', ')}]`);

    return result;
  }

  /**
   * Nettoie les anciennes données (à appeler périodiquement)
   */
  cleanup() {
    const now = Date.now();
    const maxAge = 2 * 60 * 60 * 1000; // 2 heures

    // Nettoyer les timestamps
    for (const [ip, timestamp] of this.requestTimestamps) {
      if (now - timestamp > maxAge) {
        this.requestTimestamps.delete(ip);
      }
    }

    // Nettoyer l'historique des requêtes
    if (this.requestHistory) {
      for (const [ip, history] of this.requestHistory) {
        if (history.requests.length === 0 || 
            (now - Math.max(...history.requests)) > maxAge) {
          this.requestHistory.delete(ip);
        }
      }
    }

    console.log(`[BotDetection] 🧹 Cleanup completed. Active IPs: ${this.requestTimestamps.size}`);
  }
}

module.exports = BotDetection;
