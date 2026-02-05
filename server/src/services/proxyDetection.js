/**
 * Proxy/Tor/VPN Detection Service
 * Détection des connexions via proxy, Tor ou VPN
 */

const https = require('https');
const http = require('http');

class ProxyDetection {
  constructor() {
    // Headers qui indiquent un proxy
    this.proxyHeaders = [
      'via',
      'x-forwarded-for',
      'forwarded',
      'x-proxy-id',
      'proxy-connection',
      'x-real-ip',
      'x-originating-ip',
      'x-remote-ip',
      'x-remote-addr',
      'x-client-ip',
      'x-host',
      'x-forwarded-host',
      'x-forwarded-server',
      'x-forwarded-proto',
      'x-bluecoat-via'
    ];

    // Liste des nœuds de sortie Tor connus (mise à jour périodique recommandée)
    // Source: https://check.torproject.org/torbulkexitlist
    this.torExitNodes = new Set([
      // Cette liste est un exemple - en production, charger depuis un fichier ou API
    ]);

    // Organisations VPN connues
    this.vpnOrganizations = [
      'nordvpn', 'expressvpn', 'surfshark', 'cyberghost', 'private internet access',
      'protonvpn', 'proton vpn', 'mullvad', 'windscribe', 'hotspot shield',
      'ipvanish', 'vyprvpn', 'tunnelbear', 'hide.me', 'purevpn',
      'zenmate', 'strongvpn', 'perfect privacy', 'astrill', 'airvpn',
      'privatevpn', 'trust.zone', 'ivpn', 'freedome', 'betternet',
      'vpn unlimited', 'goose vpn', 'safervpn', 'vpnarea', 'torguard',
      'vpn.ac', 'vpn.ht', 'vpn gate', 'vpnbook', 'securitykiss'
    ];

    // Organisations proxy connues
    this.proxyOrganizations = [
      'proxy', 'anonymizer', 'anonymous', 'hide', 'mask',
      'cloak', 'shield', 'guard', 'protect', 'privacy',
      'squid', 'privoxy', 'tinyproxy', 'ccproxy',
      'luminati', 'bright data', 'oxylabs', 'smartproxy',
      'geosurf', 'microleaves', 'storm proxies'
    ];

    // Cache pour les résultats
    this.cache = new Map();
    this.cacheExpiry = 30 * 60 * 1000; // 30 minutes

    console.log('[ProxyDetection] 🔒 Service initialized');
  }

  /**
   * Détecte si une connexion utilise un proxy, Tor ou VPN
   * @param {string} ip - L'adresse IP à vérifier
   * @param {object} headers - Les headers HTTP de la requête
   * @returns {Promise<object>} - Résultat de la détection
   */
  async detect(ip, headers = {}) {
    // Vérifier le cache
    const cached = this.getFromCache(ip);
    if (cached) {
      console.log(`[ProxyDetection] 📦 Cache hit for ${ip}`);
      return cached;
    }

    const result = {
      ip,
      isProxy: false,
      isTor: false,
      isVPN: false,
      isAnonymous: false,
      reasons: [],
      confidence: 0,
      details: {}
    };

    // 1. Vérifier les headers proxy
    const headerCheck = this.checkProxyHeaders(headers);
    if (headerCheck.detected) {
      result.isProxy = true;
      result.reasons.push('proxy_headers_detected');
      result.details.proxyHeaders = headerCheck.headers;
      result.confidence += 30;
    }

    // 2. Vérifier si c'est un nœud Tor
    if (this.isTorExitNode(ip)) {
      result.isTor = true;
      result.isAnonymous = true;
      result.reasons.push('tor_exit_node');
      result.confidence += 100;
    }

    // 3. Vérifier via API externe
    try {
      const apiResult = await this.checkWithAPI(ip);
      
      if (apiResult.proxy) {
        result.isProxy = true;
        result.reasons.push('api_proxy_flag');
        result.confidence += 50;
      }
      
      if (apiResult.tor) {
        result.isTor = true;
        result.isAnonymous = true;
        result.reasons.push('api_tor_flag');
        result.confidence += 80;
      }
      
      if (apiResult.vpn) {
        result.isVPN = true;
        result.isAnonymous = true;
        result.reasons.push('api_vpn_flag');
        result.confidence += 60;
      }

      // Vérifier l'organisation
      if (apiResult.org) {
        if (this.isVPNOrganization(apiResult.org)) {
          result.isVPN = true;
          result.isAnonymous = true;
          result.reasons.push('vpn_organization');
          result.confidence += 40;
        }
        
        if (this.isProxyOrganization(apiResult.org)) {
          result.isProxy = true;
          result.reasons.push('proxy_organization');
          result.confidence += 40;
        }
      }

      result.details.api = apiResult;
    } catch (error) {
      console.error(`[ProxyDetection] ❌ API check failed for ${ip}:`, error.message);
      result.details.apiError = error.message;
    }

    // Normaliser la confiance
    result.confidence = Math.min(100, result.confidence);
    result.isAnonymous = result.isProxy || result.isTor || result.isVPN;

    // Mettre en cache
    this.setCache(ip, result);

    console.log(`[ProxyDetection] 🔍 ${ip}: proxy=${result.isProxy}, tor=${result.isTor}, vpn=${result.isVPN}, confidence=${result.confidence}%`);

    return result;
  }

  /**
   * Vérifie les headers pour détecter un proxy
   * NOTE: On ignore x-forwarded-for, x-real-ip car ils sont normaux derrière CDN/load balancer
   */
  checkProxyHeaders(headers) {
    const detectedHeaders = [];
    
    // Headers à ignorer (normaux derrière CDN/load balancer)
    const ignoredHeaders = [
      'x-forwarded-for',
      'x-real-ip',
      'x-forwarded-proto',
      'x-forwarded-host',
      'x-forwarded-server',
      'forwarded'
    ];

    for (const header of this.proxyHeaders) {
      // Ignorer les headers normaux de CDN/load balancer
      if (ignoredHeaders.includes(header.toLowerCase())) {
        continue;
      }
      
      // Vérifier les deux formats (avec et sans tirets)
      const normalizedHeader = header.toLowerCase();
      const underscoreHeader = normalizedHeader.replace(/-/g, '_');
      
      if (headers[normalizedHeader] || headers[underscoreHeader]) {
        detectedHeaders.push(header);
      }
    }

    return {
      detected: detectedHeaders.length > 0,
      headers: detectedHeaders
    };
  }

  /**
   * Vérifie si l'IP est un nœud de sortie Tor
   */
  isTorExitNode(ip) {
    return this.torExitNodes.has(ip);
  }

  /**
   * Vérifie si l'organisation est un fournisseur VPN
   */
  isVPNOrganization(org) {
    if (!org) return false;
    const orgLower = org.toLowerCase();
    return this.vpnOrganizations.some(vpn => orgLower.includes(vpn));
  }

  /**
   * Vérifie si l'organisation est un fournisseur proxy
   */
  isProxyOrganization(org) {
    if (!org) return false;
    const orgLower = org.toLowerCase();
    return this.proxyOrganizations.some(proxy => orgLower.includes(proxy));
  }

  /**
   * Vérifie via l'API ip-api.com
   */
  checkWithAPI(ip) {
    return new Promise((resolve, reject) => {
      const url = `http://ip-api.com/json/${ip}?fields=status,message,proxy,hosting,org,isp,as`;
      
      const request = http.get(url, (res) => {
        let data = '';
        
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try {
            const result = JSON.parse(data);
            
            if (result.status !== 'success') {
              reject(new Error(result.message || 'API error'));
              return;
            }

            resolve({
              proxy: result.proxy || false,
              hosting: result.hosting || false,
              tor: false, // ip-api.com ne détecte pas Tor directement
              vpn: result.hosting && this.isVPNOrganization(result.org),
              org: result.org,
              isp: result.isp,
              as: result.as
            });
          } catch (error) {
            reject(error);
          }
        });
      });

      request.on('error', reject);
      request.setTimeout(5000, () => {
        request.destroy();
        reject(new Error('Timeout'));
      });
    });
  }

  /**
   * Met à jour la liste des nœuds de sortie Tor
   * À appeler périodiquement (ex: toutes les heures)
   */
  async updateTorExitNodes() {
    try {
      const response = await this.fetchTorExitNodes();
      this.torExitNodes = new Set(response);
      console.log(`[ProxyDetection] 🧅 Updated Tor exit nodes: ${this.torExitNodes.size} nodes`);
    } catch (error) {
      console.error('[ProxyDetection] ❌ Failed to update Tor exit nodes:', error.message);
    }
  }

  /**
   * Récupère la liste des nœuds de sortie Tor
   */
  fetchTorExitNodes() {
    return new Promise((resolve, reject) => {
      const url = 'https://check.torproject.org/torbulkexitlist';
      
      const request = https.get(url, (res) => {
        let data = '';
        
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          const nodes = data.split('\n')
            .map(line => line.trim())
            .filter(line => line && !line.startsWith('#'));
          resolve(nodes);
        });
      });

      request.on('error', reject);
      request.setTimeout(10000, () => {
        request.destroy();
        reject(new Error('Timeout'));
      });
    });
  }

  /**
   * Obtient un résultat du cache
   */
  getFromCache(ip) {
    const cached = this.cache.get(ip);
    if (!cached) return null;
    
    if (Date.now() > cached.expiry) {
      this.cache.delete(ip);
      return null;
    }
    
    return cached.data;
  }

  /**
   * Stocke un résultat dans le cache
   */
  setCache(ip, data) {
    const expiry = Date.now() + this.cacheExpiry;
    this.cache.set(ip, { data, expiry });
  }

  /**
   * Nettoie le cache expiré
   */
  cleanupCache() {
    const now = Date.now();
    for (const [ip, cached] of this.cache) {
      if (now > cached.expiry) {
        this.cache.delete(ip);
      }
    }
    console.log(`[ProxyDetection] 🧹 Cache cleanup. Entries: ${this.cache.size}`);
  }
}

module.exports = ProxyDetection;
