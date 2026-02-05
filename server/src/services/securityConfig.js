/**
 * Security Configuration
 * Configuration centralisée pour tous les services de sécurité
 */

const fs = require('fs');
const path = require('path');

class SecurityConfig {
  constructor() {
    this.configPath = path.join(__dirname, '..', '..', '..', 'security-config.json');
    
    // Configuration par défaut
    this.config = {
      // Actions de blocage
      blocking: {
        blockDatacenter: true,
        blockDatacenterEvenIfCountryAllowed: true,
        blockProxy: true,
        blockTor: true,
        blockVPN: true
      },
      
      // Seuils de score
      thresholds: {
        minBehaviorScore: 50,
        minFingerprintScore: 50,
        minOverallScore: 40
      },
      
      // Rate limiting
      rateLimit: {
        requestsPerMinute: 30,
        requestsPerHour: 200,
        blockDurations: [60, 300, 900, 3600] // secondes: 1min, 5min, 15min, 1h
      },
      
      // Pays autorisés (whitelist)
      allowedCountries: [],
      
      // IPs bloquées (blacklist)
      blockedIPs: [],
      
      // User-Agents bloqués
      blockedUserAgents: [],
      
      // Mode de fonctionnement
      mode: 'strict', // 'strict', 'moderate', 'permissive'
      
      // Logging
      logging: {
        logBlocked: true,
        logSuspicious: true,
        sendTelegramAlerts: true
      }
    };

    // Charger la configuration depuis le fichier si disponible
    this.loadConfig();

    console.log('[SecurityConfig] ⚙️ Configuration loaded');
    console.log('[SecurityConfig] Mode:', this.config.mode);
    console.log('[SecurityConfig] Blocking:', JSON.stringify(this.config.blocking));
  }

  /**
   * Charge la configuration depuis le fichier
   */
  loadConfig() {
    try {
      if (fs.existsSync(this.configPath)) {
        const fileContent = fs.readFileSync(this.configPath, 'utf8');
        const fileConfig = JSON.parse(fileContent);
        
        // Fusionner avec la configuration par défaut
        this.config = this.mergeConfig(this.config, fileConfig);
        console.log('[SecurityConfig] ✅ Configuration loaded from file');
      } else {
        // Créer le fichier de configuration par défaut
        this.saveConfig();
        console.log('[SecurityConfig] 📄 Default configuration file created');
      }
    } catch (error) {
      console.error('[SecurityConfig] ❌ Error loading config:', error.message);
    }
  }

  /**
   * Sauvegarde la configuration dans le fichier
   */
  saveConfig() {
    try {
      fs.writeFileSync(this.configPath, JSON.stringify(this.config, null, 2));
      console.log('[SecurityConfig] 💾 Configuration saved');
    } catch (error) {
      console.error('[SecurityConfig] ❌ Error saving config:', error.message);
    }
  }

  /**
   * Fusionne deux configurations
   */
  mergeConfig(defaultConfig, newConfig) {
    const merged = { ...defaultConfig };
    
    for (const key of Object.keys(newConfig)) {
      if (typeof newConfig[key] === 'object' && !Array.isArray(newConfig[key])) {
        merged[key] = this.mergeConfig(defaultConfig[key] || {}, newConfig[key]);
      } else {
        merged[key] = newConfig[key];
      }
    }
    
    return merged;
  }

  /**
   * Obtient une valeur de configuration
   */
  get(key) {
    const keys = key.split('.');
    let value = this.config;
    
    for (const k of keys) {
      if (value === undefined) return undefined;
      value = value[k];
    }
    
    return value;
  }

  /**
   * Définit une valeur de configuration
   */
  set(key, value) {
    const keys = key.split('.');
    let obj = this.config;
    
    for (let i = 0; i < keys.length - 1; i++) {
      if (!obj[keys[i]]) obj[keys[i]] = {};
      obj = obj[keys[i]];
    }
    
    obj[keys[keys.length - 1]] = value;
    this.saveConfig();
  }

  /**
   * Vérifie si le blocage datacenter est activé
   */
  shouldBlockDatacenter(countryAllowed = false) {
    if (!this.config.blocking.blockDatacenter) return false;
    if (countryAllowed && !this.config.blocking.blockDatacenterEvenIfCountryAllowed) return false;
    return true;
  }

  /**
   * Vérifie si le blocage proxy est activé
   */
  shouldBlockProxy() {
    return this.config.blocking.blockProxy;
  }

  /**
   * Vérifie si le blocage Tor est activé
   */
  shouldBlockTor() {
    return this.config.blocking.blockTor;
  }

  /**
   * Vérifie si le blocage VPN est activé
   */
  shouldBlockVPN() {
    return this.config.blocking.blockVPN;
  }

  /**
   * Obtient le score minimum de comportement
   */
  getMinBehaviorScore() {
    return this.config.thresholds.minBehaviorScore;
  }

  /**
   * Obtient le score minimum de fingerprint
   */
  getMinFingerprintScore() {
    return this.config.thresholds.minFingerprintScore;
  }

  /**
   * Obtient les limites de rate limiting
   */
  getRateLimits() {
    return this.config.rateLimit;
  }

  /**
   * Vérifie si un pays est autorisé
   */
  isCountryAllowed(countryCode) {
    if (this.config.allowedCountries.length === 0) return true;
    return this.config.allowedCountries.includes(countryCode.toUpperCase());
  }

  /**
   * Vérifie si une IP est bloquée
   */
  isIPBlocked(ip) {
    return this.config.blockedIPs.includes(ip);
  }

  /**
   * Ajoute une IP à la blacklist
   */
  blockIP(ip) {
    if (!this.config.blockedIPs.includes(ip)) {
      this.config.blockedIPs.push(ip);
      this.saveConfig();
    }
  }

  /**
   * Retire une IP de la blacklist
   */
  unblockIP(ip) {
    const index = this.config.blockedIPs.indexOf(ip);
    if (index > -1) {
      this.config.blockedIPs.splice(index, 1);
      this.saveConfig();
    }
  }

  /**
   * Obtient la configuration complète
   */
  getAll() {
    return { ...this.config };
  }

  /**
   * Alias pour getAll()
   */
  getConfig() {
    return this.getAll();
  }

  /**
   * Met à jour la configuration
   */
  updateConfig(newConfig) {
    this.config = this.mergeConfig(this.config, newConfig);
    this.saveConfig();
    console.log('[SecurityConfig] ✅ Configuration updated via API');
    return this.config;
  }

  /**
   * Réinitialise la configuration par défaut
   */
  reset() {
    this.config = {
      blocking: {
        blockDatacenter: true,
        blockDatacenterEvenIfCountryAllowed: true,
        blockProxy: true,
        blockTor: true,
        blockVPN: true
      },
      thresholds: {
        minBehaviorScore: 50,
        minFingerprintScore: 50,
        minOverallScore: 40
      },
      rateLimit: {
        requestsPerMinute: 30,
        requestsPerHour: 200,
        blockDurations: [60, 300, 900, 3600]
      },
      allowedCountries: [],
      blockedIPs: [],
      blockedUserAgents: [],
      mode: 'strict',
      logging: {
        logBlocked: true,
        logSuspicious: true,
        sendTelegramAlerts: true
      }
    };
    this.saveConfig();
  }
}

module.exports = SecurityConfig;
