/**
 * Visit Logger Service
 * Journalisation des visites en temps réel
 * - Compteurs persistants illimités
 * - Affichage limité aux 100 dernières visites
 */

const fs = require('fs');
const path = require('path');

class VisitLogger {
  constructor() {
    this.logFile = path.join(__dirname, '..', '..', '..', 'visits.json');
    this.statsFile = path.join(__dirname, '..', '..', '..', 'visits-stats.json');
    this.visits = [];
    this.maxDisplayVisits = 100; // Afficher seulement les 100 dernières visites

    // Compteurs persistants (jamais effacés sauf manuellement)
    this.stats = {
      total: 0,
      allowed: 0,
      blocked: 0,
      bots: 0,
      datacenters: 0,
      proxies: 0,
      vpns: 0,
      tor: 0,
      countryCounts: {},
      firstVisit: null,
      lastVisit: null
    };

    // Charger les données existantes
    this.loadVisits();
    this.loadStats();

    console.log('[VisitLogger] 📝 Service initialized');
    console.log(`[VisitLogger] 📊 Total visits recorded: ${this.stats.total}`);
  }

  /**
   * Charge les visites depuis le fichier
   */
  loadVisits() {
    try {
      if (fs.existsSync(this.logFile)) {
        const content = fs.readFileSync(this.logFile, 'utf8');
        this.visits = JSON.parse(content);
        console.log(`[VisitLogger] 📂 Loaded ${this.visits.length} recent visits from file`);
      }
    } catch (error) {
      console.error('[VisitLogger] ❌ Error loading visits:', error.message);
      this.visits = [];
    }
  }

  /**
   * Charge les statistiques persistantes
   */
  loadStats() {
    try {
      if (fs.existsSync(this.statsFile)) {
        const content = fs.readFileSync(this.statsFile, 'utf8');
        const savedStats = JSON.parse(content);
        this.stats = { ...this.stats, ...savedStats };
        console.log(`[VisitLogger] 📊 Loaded persistent stats - Total: ${this.stats.total}`);
      }
    } catch (error) {
      console.error('[VisitLogger] ❌ Error loading stats:', error.message);
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
   * Sauvegarde les statistiques persistantes
   */
  saveStats() {
    try {
      fs.writeFileSync(this.statsFile, JSON.stringify(this.stats, null, 2));
    } catch (error) {
      console.error('[VisitLogger] ❌ Error saving stats:', error.message);
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

    // Ajouter au début du tableau des visites récentes
    this.visits.unshift(visit);

    // Limiter l'affichage aux 100 dernières visites
    if (this.visits.length > this.maxDisplayVisits) {
      this.visits = this.visits.slice(0, this.maxDisplayVisits);
    }

    // Mettre à jour les compteurs persistants (JAMAIS effacés)
    this.updateStats(visit);

    // Sauvegarder
    this.saveVisits();
    this.saveStats();

    console.log(`[VisitLogger] 📝 Visit logged: ${visit.ip} (${visit.country}) - ${visit.status} | Total: ${this.stats.total}`);

    return visit;
  }

  /**
   * Met à jour les statistiques persistantes
   * @param {object} visit - Données de la visite
   */
  updateStats(visit) {
    // Compteur total
    this.stats.total++;

    // Compteurs par status
    if (visit.status === 'blocked') {
      this.stats.blocked++;
    } else {
      this.stats.allowed++;
    }

    // Compteurs par type de détection
    if (visit.detection.isBot) {
      this.stats.bots++;
    }
    if (visit.detection.isDatacenter) {
      this.stats.datacenters++;
    }
    if (visit.detection.isProxy) {
      this.stats.proxies++;
    }
    if (visit.detection.isVPN) {
      this.stats.vpns++;
    }
    if (visit.detection.isTor) {
      this.stats.tor++;
    }

    // Compteur par pays
    const country = visit.countryCode || 'XX';
    this.stats.countryCounts[country] = (this.stats.countryCounts[country] || 0) + 1;

    // Dates
    if (!this.stats.firstVisit) {
      this.stats.firstVisit = visit.timestamp;
    }
    this.stats.lastVisit = visit.timestamp;
  }

  /**
   * Obtient les visites récentes (pour affichage)
   * @param {number} limit - Nombre max de visites à retourner
   * @returns {Array} - Liste des visites
   */
  getVisits(limit = 100) {
    return this.visits.slice(0, Math.min(limit, this.maxDisplayVisits));
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
   * Obtient les statistiques persistantes (compteurs illimités)
   * @returns {object} - Statistiques
   */
  getStats() {
    // Top 5 pays
    const topCountries = Object.entries(this.stats.countryCounts || {})
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([code, count]) => ({ code, count }));

    return {
      // Compteurs persistants (jamais effacés)
      total: this.stats.total,
      allowed: this.stats.allowed,
      blocked: this.stats.blocked,
      
      // Détections persistantes
      detections: {
        bots: this.stats.bots,
        datacenters: this.stats.datacenters,
        proxies: this.stats.proxies,
        vpns: this.stats.vpns,
        tor: this.stats.tor
      },
      
      // Infos temporelles
      firstVisit: this.stats.firstVisit,
      lastVisit: this.stats.lastVisit,
      
      // Top pays
      topCountries,
      
      // Nombre de visites affichées actuellement
      displayedVisits: this.visits.length
    };
  }

  /**
   * Efface uniquement la liste des visites récentes (pas les compteurs!)
   */
  clearVisits() {
    this.visits = [];
    this.saveVisits();
    console.log('[VisitLogger] 🗑️ Recent visits list cleared (stats preserved)');
    console.log(`[VisitLogger] 📊 Stats still show: Total=${this.stats.total}, Blocked=${this.stats.blocked}, Bots=${this.stats.bots}`);
  }

  /**
   * Réinitialise TOUT (visites ET compteurs) - À utiliser avec précaution
   */
  resetAll() {
    this.visits = [];
    this.stats = {
      total: 0,
      allowed: 0,
      blocked: 0,
      bots: 0,
      datacenters: 0,
      proxies: 0,
      vpns: 0,
      tor: 0,
      countryCounts: {},
      firstVisit: null,
      lastVisit: null
    };
    this.saveVisits();
    this.saveStats();
    console.log('[VisitLogger] ⚠️ ALL data reset (visits AND stats)');
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
      console.log(`[VisitLogger] 🧹 Cleaned up ${removed} old visits from display list`);
    }
  }
}

module.exports = VisitLogger;
