/**
 * Visit Logger Service
 * Journalisation des visites en temps réel
 */

const fs = require('fs');
const path = require('path');

class VisitLogger {
  constructor() {
    this.logFile = path.join(__dirname, '..', '..', '..', 'visits.json');
    this.visits = [];
    this.maxVisits = 500; // Garder les 500 dernières visites

    // Charger les visites existantes
    this.loadVisits();

    console.log('[VisitLogger] 📝 Service initialized');
  }

  /**
   * Charge les visites depuis le fichier
   */
  loadVisits() {
    try {
      if (fs.existsSync(this.logFile)) {
        const content = fs.readFileSync(this.logFile, 'utf8');
        this.visits = JSON.parse(content);
        console.log(`[VisitLogger] 📂 Loaded ${this.visits.length} visits from file`);
      }
    } catch (error) {
      console.error('[VisitLogger] ❌ Error loading visits:', error.message);
      this.visits = [];
    }
  }

  /**
   * Sauvegarde les visites dans le fichier
   */
  saveVisits() {
    try {
      fs.writeFileSync(this.logFile, JSON.stringify(this.visits, null, 2));
    } catch (error) {
      console.error('[VisitLogger] ❌ Error saving visits:', error.message);
    }
  }

  /**
   * Enregistre une nouvelle visite
   * @param {object} visitData - Données de la visite
   */
  logVisit(visitData) {
    const visit = {
      id: Date.now().toString(36) + Math.random().toString(36).substr(2, 5),
      timestamp: new Date().toISOString(),
      ip: visitData.ip || 'Unknown',
      country: visitData.country || 'Unknown',
      countryCode: visitData.countryCode || 'XX',
      userAgent: visitData.userAgent || 'Unknown',
      
      // Détections
      detection: {
        isBot: visitData.isBot || false,
        botScore: visitData.botScore || 100,
        botReasons: visitData.botReasons || [],
        
        isDatacenter: visitData.isDatacenter || false,
        datacenterOrg: visitData.datacenterOrg || null,
        
        isProxy: visitData.isProxy || false,
        isTor: visitData.isTor || false,
        isVPN: visitData.isVPN || false,
        
        isBlocked: visitData.isBlocked || false,
        blockReason: visitData.blockReason || null
      },
      
      // Infos supplémentaires
      clientId: visitData.clientId || null,
      page: visitData.page || '/',
      referer: visitData.referer || null,
      
      // Status
      status: visitData.isBlocked ? 'blocked' : 'allowed'
    };

    // Ajouter au début du tableau
    this.visits.unshift(visit);

    // Limiter le nombre de visites
    if (this.visits.length > this.maxVisits) {
      this.visits = this.visits.slice(0, this.maxVisits);
    }

    // Sauvegarder
    this.saveVisits();

    console.log(`[VisitLogger] 📝 Visit logged: ${visit.ip} (${visit.country}) - ${visit.status}`);

    return visit;
  }

  /**
   * Obtient toutes les visites
   * @param {number} limit - Nombre max de visites à retourner
   * @returns {Array} - Liste des visites
   */
  getVisits(limit = 100) {
    return this.visits.slice(0, limit);
  }

  /**
   * Obtient les visites filtrées
   * @param {object} filters - Filtres à appliquer
   * @returns {Array} - Liste des visites filtrées
   */
  getFilteredVisits(filters = {}) {
    let result = [...this.visits];

    if (filters.status) {
      result = result.filter(v => v.status === filters.status);
    }

    if (filters.country) {
      result = result.filter(v => v.countryCode === filters.country);
    }

    if (filters.isBot !== undefined) {
      result = result.filter(v => v.detection.isBot === filters.isBot);
    }

    if (filters.limit) {
      result = result.slice(0, filters.limit);
    }

    return result;
  }

  /**
   * Obtient les statistiques des visites
   * @returns {object} - Statistiques
   */
  getStats() {
    const now = new Date();
    const oneHourAgo = new Date(now - 60 * 60 * 1000);
    const oneDayAgo = new Date(now - 24 * 60 * 60 * 1000);

    const visitsLastHour = this.visits.filter(v => new Date(v.timestamp) > oneHourAgo);
    const visitsLastDay = this.visits.filter(v => new Date(v.timestamp) > oneDayAgo);

    const blockedLastHour = visitsLastHour.filter(v => v.status === 'blocked').length;
    const blockedLastDay = visitsLastDay.filter(v => v.status === 'blocked').length;

    // Compter par pays
    const countryCounts = {};
    this.visits.forEach(v => {
      const country = v.countryCode || 'XX';
      countryCounts[country] = (countryCounts[country] || 0) + 1;
    });

    // Top 5 pays
    const topCountries = Object.entries(countryCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([code, count]) => ({ code, count }));

    return {
      total: this.visits.length,
      lastHour: {
        total: visitsLastHour.length,
        allowed: visitsLastHour.length - blockedLastHour,
        blocked: blockedLastHour
      },
      lastDay: {
        total: visitsLastDay.length,
        allowed: visitsLastDay.length - blockedLastDay,
        blocked: blockedLastDay
      },
      topCountries,
      detections: {
        bots: this.visits.filter(v => v.detection.isBot).length,
        datacenters: this.visits.filter(v => v.detection.isDatacenter).length,
        proxies: this.visits.filter(v => v.detection.isProxy).length,
        vpns: this.visits.filter(v => v.detection.isVPN).length,
        tor: this.visits.filter(v => v.detection.isTor).length
      }
    };
  }

  /**
   * Efface toutes les visites
   */
  clearVisits() {
    this.visits = [];
    this.saveVisits();
    console.log('[VisitLogger] 🗑️ All visits cleared');
  }

  /**
   * Efface les visites plus anciennes qu'une certaine date
   * @param {number} maxAge - Age max en millisecondes
   */
  cleanupOldVisits(maxAge = 7 * 24 * 60 * 60 * 1000) { // 7 jours par défaut
    const cutoff = new Date(Date.now() - maxAge);
    const before = this.visits.length;
    this.visits = this.visits.filter(v => new Date(v.timestamp) > cutoff);
    const removed = before - this.visits.length;
    
    if (removed > 0) {
      this.saveVisits();
      console.log(`[VisitLogger] 🧹 Cleaned up ${removed} old visits`);
    }
  }
}

module.exports = VisitLogger;
