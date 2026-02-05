/**
 * Datacenter Detection Service
 * Détection des IPs provenant de datacenters, hébergeurs et clouds
 */

const https = require('https');
const http = require('http');

class DatacenterDetection {
  constructor() {
    // Liste des organisations de datacenter connues (60+)
    this.datacenterOrganizations = [
      // Cloud majeurs
      'amazon', 'aws', 'ec2', 'cloudfront',
      'google', 'gcp', 'google cloud',
      'microsoft', 'azure', 'microsoft azure',
      'digitalocean', 'linode', 'vultr', 'hetzner',
      'ovh', 'ovhcloud', 'kimsufi', 'soyoustart',
      'scaleway', 'online.net', 'iliad',
      'rackspace', 'softlayer', 'ibm cloud',
      'oracle cloud', 'alibaba cloud', 'aliyun',
      'tencent cloud', 'huawei cloud',
      
      // Hébergeurs populaires
      'godaddy', 'hostgator', 'bluehost', 'dreamhost',
      'namecheap', 'hostinger', 'siteground', 'a2hosting',
      'ionos', '1&1', 'strato', 'contabo',
      'hostwinds', 'interserver', 'liquidweb',
      'inmotion', 'greengeeks', 'fastcomet',
      
      // VPS/Dédié
      'choopa', 'vultr', 'datapacket', 'servermania',
      'phoenixnap', 'leaseweb', 'cogent', 'zayo',
      'quadranet', 'psychz', 'fdcservers',
      
      // CDN
      'cloudflare', 'akamai', 'fastly', 'stackpath',
      'keycdn', 'bunny', 'cdn77', 'jsdelivr',
      
      // Autres datacenters
      'datacenter', 'hosting', 'server', 'vps',
      'dedicated', 'colocation', 'colo',
      'data center', 'cloud services'
    ];

    // Liste des ASN de datacenter connus (30+)
    this.datacenterASNs = [
      // Amazon
      '16509', '14618', '7224',
      // Google
      '15169', '396982', '36040',
      // Microsoft
      '8075', '8068', '8069',
      // DigitalOcean
      '14061', '393406',
      // OVH
      '16276',
      // Hetzner
      '24940',
      // Linode
      '63949',
      // Vultr/Choopa
      '20473',
      // Cloudflare
      '13335',
      // Akamai
      '20940', '16625',
      // Oracle
      '31898',
      // Alibaba
      '45102',
      // Tencent
      '45090',
      // Scaleway
      '12876',
      // Contabo
      '51167',
      // Leaseweb
      '60781', '28753'
    ];

    // Cache pour les résultats (évite les appels API répétés)
    this.cache = new Map();
    this.cacheExpiry = {
      normal: 24 * 60 * 60 * 1000, // 24h pour IPs normales
      datacenter: 1 * 60 * 60 * 1000 // 1h pour datacenters
    };

    console.log('[DatacenterDetection] 🏢 Service initialized');
    console.log(`[DatacenterDetection] Organizations: ${this.datacenterOrganizations.length}`);
    console.log(`[DatacenterDetection] ASNs: ${this.datacenterASNs.length}`);
  }

  /**
   * Vérifie si une IP provient d'un datacenter
   * @param {string} ip - L'adresse IP à vérifier
   * @returns {Promise<object>} - Résultat de la détection
   */
  async detect(ip) {
    // Vérifier le cache
    const cached = this.getFromCache(ip);
    if (cached) {
      console.log(`[DatacenterDetection] 📦 Cache hit for ${ip}`);
      return cached;
    }

    // Ignorer les IPs locales
    if (this.isLocalIP(ip)) {
      const result = { isDatacenter: false, reason: 'local_ip', ip };
      this.setCache(ip, result, false);
      return result;
    }

    try {
      // Essayer d'abord avec ip-api.com
      const result = await this.checkWithIPAPI(ip);
      this.setCache(ip, result, result.isDatacenter);
      return result;
    } catch (error) {
      console.error(`[DatacenterDetection] ❌ Error detecting datacenter for ${ip}:`, error.message);
      
      // Essayer l'API alternative
      try {
        const result = await this.checkWithIPAPIco(ip);
        this.setCache(ip, result, result.isDatacenter);
        return result;
      } catch (error2) {
        console.error(`[DatacenterDetection] ❌ Fallback API also failed:`, error2.message);
        return { isDatacenter: false, reason: 'api_error', ip, error: error.message };
      }
    }
  }

  /**
   * Vérifie avec ip-api.com
   */
  checkWithIPAPI(ip) {
    return new Promise((resolve, reject) => {
      const url = `http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,region,city,isp,org,as,hosting,proxy,mobile`;
      
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

            const isDatacenter = this.analyzeResult(result);
            
            resolve({
              ip,
              isDatacenter: isDatacenter.detected,
              isHosting: result.hosting || false,
              isProxy: result.proxy || false,
              isMobile: result.mobile || false,
              org: result.org,
              isp: result.isp,
              as: result.as,
              country: result.country,
              countryCode: result.countryCode,
              city: result.city,
              reasons: isDatacenter.reasons,
              source: 'ip-api.com'
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
   * Vérifie avec ipapi.co (API alternative)
   */
  checkWithIPAPIco(ip) {
    return new Promise((resolve, reject) => {
      const url = `https://ipapi.co/${ip}/json/`;
      
      const request = https.get(url, (res) => {
        let data = '';
        
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try {
            const result = JSON.parse(data);
            
            if (result.error) {
              reject(new Error(result.reason || 'API error'));
              return;
            }

            const org = result.org || '';
            const asn = result.asn || '';
            
            const isDatacenter = this.checkOrganization(org) || this.checkASN(asn);
            
            resolve({
              ip,
              isDatacenter,
              isHosting: isDatacenter,
              isProxy: false, // ipapi.co ne fournit pas cette info
              org: result.org,
              isp: result.org,
              as: result.asn,
              country: result.country_name,
              countryCode: result.country_code,
              city: result.city,
              reasons: isDatacenter ? ['organization_match'] : [],
              source: 'ipapi.co'
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
   * Analyse le résultat de l'API pour détecter un datacenter
   */
  analyzeResult(result) {
    const reasons = [];

    // 1. Flag hosting de l'API
    if (result.hosting) {
      reasons.push('hosting_flag');
    }

    // 2. Flag proxy de l'API
    if (result.proxy) {
      reasons.push('proxy_flag');
    }

    // 3. Vérifier l'organisation
    if (this.checkOrganization(result.org)) {
      reasons.push('organization_match');
    }

    // 4. Vérifier l'ISP
    if (this.checkOrganization(result.isp)) {
      reasons.push('isp_match');
    }

    // 5. Vérifier l'ASN
    if (result.as && this.checkASN(result.as)) {
      reasons.push('asn_match');
    }

    return {
      detected: reasons.length > 0,
      reasons
    };
  }

  /**
   * Vérifie si l'organisation correspond à un datacenter
   */
  checkOrganization(org) {
    if (!org) return false;
    const orgLower = org.toLowerCase();
    return this.datacenterOrganizations.some(dc => orgLower.includes(dc));
  }

  /**
   * Vérifie si l'ASN correspond à un datacenter
   */
  checkASN(as) {
    if (!as) return false;
    // Extraire le numéro ASN (format: "AS12345 Organization Name")
    const asnMatch = as.match(/AS(\d+)/i);
    if (asnMatch) {
      return this.datacenterASNs.includes(asnMatch[1]);
    }
    return false;
  }

  /**
   * Vérifie si c'est une IP locale
   */
  isLocalIP(ip) {
    return !ip || 
           ip === 'unknown' || 
           ip === '127.0.0.1' || 
           ip === '::1' || 
           ip.startsWith('192.168.') || 
           ip.startsWith('10.') || 
           ip.startsWith('172.16.') ||
           ip.startsWith('172.17.') ||
           ip.startsWith('172.18.') ||
           ip.startsWith('172.19.') ||
           ip.startsWith('172.2') ||
           ip.startsWith('172.30.') ||
           ip.startsWith('172.31.');
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
  setCache(ip, data, isDatacenter) {
    const expiry = Date.now() + (isDatacenter ? this.cacheExpiry.datacenter : this.cacheExpiry.normal);
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
    console.log(`[DatacenterDetection] 🧹 Cache cleanup. Entries: ${this.cache.size}`);
  }
}

module.exports = DatacenterDetection;
