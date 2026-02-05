/**
 * Fingerprint Service
 * Analyse et validation des empreintes de navigateur
 */

class FingerprintService {
  constructor() {
    // Score minimum pour être considéré légitime
    this.minScore = 50;

    // Poids des différents critères
    this.weights = {
      userAgent: 10,
      headers: 15,
      screen: 10,
      timezone: 10,
      language: 10,
      plugins: 10,
      canvas: 15,
      webgl: 10,
      fonts: 10
    };

    // User-Agents de navigateurs légitimes
    this.legitimateBrowsers = [
      'chrome', 'firefox', 'safari', 'edge', 'opera', 'brave'
    ];

    // Headers attendus pour un navigateur légitime
    this.expectedHeaders = [
      'accept',
      'accept-language',
      'accept-encoding',
      'connection',
      'host'
    ];

    // Résolutions d'écran courantes
    this.commonResolutions = [
      '1920x1080', '1366x768', '1536x864', '1440x900', '1280x720',
      '1600x900', '2560x1440', '3840x2160', '1280x800', '1024x768',
      '2560x1600', '1680x1050', '1920x1200', '2880x1800', '3440x1440',
      // Mobile
      '414x896', '375x812', '390x844', '428x926', '360x800',
      '412x915', '393x873', '360x780', '320x568', '375x667'
    ];

    // Timezones valides
    this.validTimezones = [
      'UTC', 'GMT',
      'America/New_York', 'America/Chicago', 'America/Denver', 'America/Los_Angeles',
      'Europe/London', 'Europe/Paris', 'Europe/Berlin', 'Europe/Rome', 'Europe/Madrid',
      'Asia/Tokyo', 'Asia/Shanghai', 'Asia/Singapore', 'Asia/Dubai',
      'Australia/Sydney', 'Pacific/Auckland',
      'Africa/Casablanca', 'Africa/Johannesburg', 'Africa/Lagos', 'Africa/Cairo'
    ];

    // Stockage des fingerprints pour détection de fraude
    this.fingerprints = new Map();

    console.log('[FingerprintService] 🔍 Service initialized');
  }

  /**
   * Analyse un fingerprint complet
   * @param {object} fingerprint - Les données du fingerprint
   * @returns {object} - Résultat de l'analyse
   */
  analyze(fingerprint) {
    if (!fingerprint) {
      return {
        score: 0,
        isLegitimate: false,
        reason: 'no_fingerprint_data'
      };
    }

    let totalScore = 0;
    const details = {};
    const flags = [];

    // 1. Analyse du User-Agent
    const uaAnalysis = this.analyzeUserAgent(fingerprint.userAgent);
    totalScore += uaAnalysis.score * (this.weights.userAgent / 100);
    details.userAgent = uaAnalysis;
    if (!uaAnalysis.isLegitimate) flags.push('suspicious_user_agent');

    // 2. Analyse des Headers
    const headerAnalysis = this.analyzeHeaders(fingerprint.headers);
    totalScore += headerAnalysis.score * (this.weights.headers / 100);
    details.headers = headerAnalysis;
    if (!headerAnalysis.isComplete) flags.push('incomplete_headers');

    // 3. Analyse de la résolution d'écran
    const screenAnalysis = this.analyzeScreen(fingerprint.screen);
    totalScore += screenAnalysis.score * (this.weights.screen / 100);
    details.screen = screenAnalysis;
    if (!screenAnalysis.isCommon) flags.push('unusual_screen');

    // 4. Analyse du timezone
    const tzAnalysis = this.analyzeTimezone(fingerprint.timezone);
    totalScore += tzAnalysis.score * (this.weights.timezone / 100);
    details.timezone = tzAnalysis;
    if (!tzAnalysis.isValid) flags.push('invalid_timezone');

    // 5. Analyse des langues
    const langAnalysis = this.analyzeLanguages(fingerprint.languages);
    totalScore += langAnalysis.score * (this.weights.language / 100);
    details.languages = langAnalysis;
    if (!langAnalysis.isValid) flags.push('no_languages');

    // 6. Analyse des plugins
    const pluginAnalysis = this.analyzePlugins(fingerprint.plugins);
    totalScore += pluginAnalysis.score * (this.weights.plugins / 100);
    details.plugins = pluginAnalysis;

    // 7. Analyse du canvas fingerprint
    const canvasAnalysis = this.analyzeCanvas(fingerprint.canvas);
    totalScore += canvasAnalysis.score * (this.weights.canvas / 100);
    details.canvas = canvasAnalysis;
    if (!canvasAnalysis.isValid) flags.push('no_canvas');

    // 8. Analyse du WebGL
    const webglAnalysis = this.analyzeWebGL(fingerprint.webgl);
    totalScore += webglAnalysis.score * (this.weights.webgl / 100);
    details.webgl = webglAnalysis;
    if (!webglAnalysis.isValid) flags.push('no_webgl');

    // 9. Analyse des fonts
    const fontAnalysis = this.analyzeFonts(fingerprint.fonts);
    totalScore += fontAnalysis.score * (this.weights.fonts / 100);
    details.fonts = fontAnalysis;

    // Normaliser le score
    const finalScore = Math.round(Math.min(100, Math.max(0, totalScore)));

    const result = {
      score: finalScore,
      isLegitimate: finalScore >= this.minScore,
      flags,
      details,
      hash: this.generateHash(fingerprint)
    };

    console.log(`[FingerprintService] 📊 Analysis: score=${finalScore}, legitimate=${result.isLegitimate}, flags=[${flags.join(', ')}]`);

    return result;
  }

  /**
   * Analyse le User-Agent
   */
  analyzeUserAgent(userAgent) {
    if (!userAgent) {
      return { score: 0, isLegitimate: false, reason: 'missing' };
    }

    const ua = userAgent.toLowerCase();
    let score = 50;

    // Vérifier si c'est un navigateur légitime
    const isLegitimate = this.legitimateBrowsers.some(browser => ua.includes(browser));
    if (isLegitimate) {
      score += 30;
    }

    // Vérifier la présence de "mozilla" (standard pour les navigateurs)
    if (ua.includes('mozilla')) {
      score += 10;
    }

    // Vérifier la présence d'un OS
    if (ua.includes('windows') || ua.includes('mac') || ua.includes('linux') || 
        ua.includes('android') || ua.includes('iphone') || ua.includes('ipad')) {
      score += 10;
    }

    // Pénaliser les User-Agents trop courts
    if (userAgent.length < 50) {
      score -= 20;
    }

    return {
      score: Math.max(0, Math.min(100, score)),
      isLegitimate,
      length: userAgent.length
    };
  }

  /**
   * Analyse les headers HTTP
   */
  analyzeHeaders(headers) {
    if (!headers) {
      return { score: 30, isComplete: false, missing: this.expectedHeaders };
    }

    const missing = [];
    let presentCount = 0;

    for (const header of this.expectedHeaders) {
      if (headers[header] || headers[header.toLowerCase()]) {
        presentCount++;
      } else {
        missing.push(header);
      }
    }

    const completeness = presentCount / this.expectedHeaders.length;
    const score = Math.round(completeness * 100);

    return {
      score,
      isComplete: missing.length === 0,
      missing,
      presentCount
    };
  }

  /**
   * Analyse la résolution d'écran
   */
  analyzeScreen(screen) {
    if (!screen || !screen.width || !screen.height) {
      return { score: 30, isCommon: false, reason: 'missing' };
    }

    const resolution = `${screen.width}x${screen.height}`;
    const isCommon = this.commonResolutions.includes(resolution);

    let score = 50;
    if (isCommon) {
      score += 40;
    }

    // Vérifier les valeurs raisonnables
    if (screen.width >= 320 && screen.width <= 7680 &&
        screen.height >= 480 && screen.height <= 4320) {
      score += 10;
    }

    // Vérifier le ratio (devrait être entre 1.0 et 2.5 pour la plupart des écrans)
    const ratio = screen.width / screen.height;
    if (ratio >= 0.5 && ratio <= 2.5) {
      score += 10;
    }

    return {
      score: Math.min(100, score),
      isCommon,
      resolution,
      ratio: ratio.toFixed(2)
    };
  }

  /**
   * Analyse le timezone
   */
  analyzeTimezone(timezone) {
    if (!timezone) {
      return { score: 40, isValid: false, reason: 'missing' };
    }

    // Vérifier si c'est un timezone valide
    const isValid = this.validTimezones.some(tz => 
      timezone.includes(tz) || tz.includes(timezone)
    );

    // Vérifier le format
    const hasValidFormat = /^[A-Za-z]+\/[A-Za-z_]+$/.test(timezone) || 
                          /^(UTC|GMT)([+-]\d{1,2})?$/.test(timezone);

    let score = 50;
    if (isValid) score += 30;
    if (hasValidFormat) score += 20;

    return {
      score: Math.min(100, score),
      isValid: isValid || hasValidFormat,
      timezone
    };
  }

  /**
   * Analyse les langues
   */
  analyzeLanguages(languages) {
    if (!languages || languages.length === 0) {
      return { score: 30, isValid: false, reason: 'missing' };
    }

    let score = 50;

    // Au moins une langue
    if (languages.length >= 1) {
      score += 20;
    }

    // Vérifier le format des langues (ex: "en-US", "fr", "fr-FR")
    const validLanguages = languages.filter(lang => 
      /^[a-z]{2}(-[A-Z]{2})?$/.test(lang)
    );

    if (validLanguages.length > 0) {
      score += 30;
    }

    return {
      score: Math.min(100, score),
      isValid: languages.length > 0,
      count: languages.length,
      languages
    };
  }

  /**
   * Analyse les plugins
   */
  analyzePlugins(plugins) {
    if (!plugins) {
      return { score: 50, count: 0 };
    }

    let score = 50;
    const count = Array.isArray(plugins) ? plugins.length : 0;

    // Les navigateurs modernes ont généralement peu de plugins visibles
    if (count >= 0 && count <= 10) {
      score += 30;
    }

    // Chrome/Edge avec PDF viewer
    if (count >= 1) {
      score += 20;
    }

    return {
      score: Math.min(100, score),
      count
    };
  }

  /**
   * Analyse le canvas fingerprint
   */
  analyzeCanvas(canvas) {
    if (!canvas) {
      return { score: 30, isValid: false, reason: 'missing' };
    }

    let score = 50;

    // Vérifier si c'est un hash valide
    if (typeof canvas === 'string' && canvas.length > 10) {
      score += 30;
    }

    // Les bots ont souvent le même canvas fingerprint
    // En production, on comparerait avec une base de fingerprints connus

    return {
      score: Math.min(100, score),
      isValid: !!canvas,
      hash: typeof canvas === 'string' ? canvas.substring(0, 20) + '...' : null
    };
  }

  /**
   * Analyse le WebGL
   */
  analyzeWebGL(webgl) {
    if (!webgl) {
      return { score: 40, isValid: false, reason: 'missing' };
    }

    let score = 50;

    // Vérifier la présence du vendor et renderer
    if (webgl.vendor) {
      score += 25;
    }
    if (webgl.renderer) {
      score += 25;
    }

    // Vendors légitimes
    const legitimateVendors = ['google', 'intel', 'nvidia', 'amd', 'apple', 'arm', 'qualcomm'];
    if (webgl.vendor) {
      const vendorLower = webgl.vendor.toLowerCase();
      if (legitimateVendors.some(v => vendorLower.includes(v))) {
        score += 10;
      }
    }

    return {
      score: Math.min(100, score),
      isValid: !!(webgl.vendor || webgl.renderer),
      vendor: webgl.vendor,
      renderer: webgl.renderer
    };
  }

  /**
   * Analyse les fonts
   */
  analyzeFonts(fonts) {
    if (!fonts) {
      return { score: 50, count: 0 };
    }

    const count = Array.isArray(fonts) ? fonts.length : 0;
    let score = 50;

    // Un système normal a généralement entre 20 et 500 fonts
    if (count >= 10 && count <= 500) {
      score += 30;
    } else if (count > 0) {
      score += 15;
    }

    // Vérifier les fonts système communes
    const commonFonts = ['arial', 'times', 'helvetica', 'verdana', 'georgia'];
    if (Array.isArray(fonts)) {
      const hasCommonFonts = fonts.some(font => 
        commonFonts.some(cf => font.toLowerCase().includes(cf))
      );
      if (hasCommonFonts) {
        score += 20;
      }
    }

    return {
      score: Math.min(100, score),
      count
    };
  }

  /**
   * Génère un hash unique pour le fingerprint
   */
  generateHash(fingerprint) {
    const data = JSON.stringify({
      ua: fingerprint.userAgent,
      screen: fingerprint.screen,
      tz: fingerprint.timezone,
      lang: fingerprint.languages,
      canvas: fingerprint.canvas,
      webgl: fingerprint.webgl
    });

    // Simple hash (en production, utiliser crypto)
    let hash = 0;
    for (let i = 0; i < data.length; i++) {
      const char = data.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return Math.abs(hash).toString(16);
  }

  /**
   * Stocke un fingerprint pour un client
   */
  storeFingerprint(clientId, fingerprint, analysis) {
    this.fingerprints.set(clientId, {
      fingerprint,
      analysis,
      timestamp: Date.now()
    });
  }

  /**
   * Vérifie si un fingerprint a déjà été vu (détection de fraude)
   */
  isDuplicateFingerprint(hash, excludeClientId = null) {
    for (const [clientId, data] of this.fingerprints) {
      if (clientId !== excludeClientId && data.analysis.hash === hash) {
        return { isDuplicate: true, clientId };
      }
    }
    return { isDuplicate: false };
  }

  /**
   * Nettoie les anciens fingerprints
   */
  cleanup(maxAge = 24 * 60 * 60 * 1000) {
    const now = Date.now();
    let removed = 0;

    for (const [clientId, data] of this.fingerprints) {
      if (now - data.timestamp > maxAge) {
        this.fingerprints.delete(clientId);
        removed++;
      }
    }

    console.log(`[FingerprintService] 🧹 Cleanup: removed ${removed} old fingerprints. Active: ${this.fingerprints.size}`);
  }
}

module.exports = FingerprintService;
