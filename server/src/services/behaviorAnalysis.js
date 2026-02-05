/**
 * Behavior Analysis Service
 * Analyse comportementale pour détecter les bots vs humains
 */

class BehaviorAnalysis {
  constructor() {
    // Stockage des données comportementales par client
    this.clientBehavior = new Map();
    
    // Seuils de détection
    this.thresholds = {
      minMouseMovements: 5,
      minKeystrokes: 3,
      minTimeOnPage: 2000, // 2 secondes minimum
      maxTimeOnPage: 300000, // 5 minutes max pour une page
      minScrollEvents: 1,
      humanTypingSpeedMin: 50, // ms entre les touches (trop rapide = bot)
      humanTypingSpeedMax: 500, // ms entre les touches (trop lent = copier/coller)
      minMouseSpeed: 0.1, // pixels/ms
      maxMouseSpeed: 50, // pixels/ms (trop rapide = bot)
      minClickDelay: 100, // ms entre les clics
    };

    // Score minimum pour être considéré humain
    this.humanScoreThreshold = 50;

    console.log('[BehaviorAnalysis] 🧠 Service initialized');
  }

  /**
   * Initialise le tracking pour un nouveau client
   * @param {string} clientId - ID du client
   */
  initClient(clientId) {
    this.clientBehavior.set(clientId, {
      startTime: Date.now(),
      mouseMovements: [],
      keystrokes: [],
      clicks: [],
      scrollEvents: [],
      formInteractions: [],
      pageViews: [],
      lastActivity: Date.now(),
      score: 50, // Score initial neutre
      flags: []
    });
    
    console.log(`[BehaviorAnalysis] 👤 Client ${clientId} initialized`);
  }

  /**
   * Enregistre un mouvement de souris
   * @param {string} clientId - ID du client
   * @param {object} data - { x, y, timestamp }
   */
  recordMouseMovement(clientId, data) {
    const behavior = this.clientBehavior.get(clientId);
    if (!behavior) return;

    behavior.mouseMovements.push({
      x: data.x,
      y: data.y,
      timestamp: data.timestamp || Date.now()
    });

    behavior.lastActivity = Date.now();

    // Garder seulement les 100 derniers mouvements
    if (behavior.mouseMovements.length > 100) {
      behavior.mouseMovements.shift();
    }
  }

  /**
   * Enregistre une frappe clavier
   * @param {string} clientId - ID du client
   * @param {object} data - { key, timestamp, field }
   */
  recordKeystroke(clientId, data) {
    const behavior = this.clientBehavior.get(clientId);
    if (!behavior) return;

    behavior.keystrokes.push({
      key: data.key ? data.key.length : 1, // Ne pas stocker la touche exacte pour la vie privée
      timestamp: data.timestamp || Date.now(),
      field: data.field
    });

    behavior.lastActivity = Date.now();

    // Garder seulement les 50 dernières frappes
    if (behavior.keystrokes.length > 50) {
      behavior.keystrokes.shift();
    }
  }

  /**
   * Enregistre un clic
   * @param {string} clientId - ID du client
   * @param {object} data - { x, y, timestamp, element }
   */
  recordClick(clientId, data) {
    const behavior = this.clientBehavior.get(clientId);
    if (!behavior) return;

    behavior.clicks.push({
      x: data.x,
      y: data.y,
      timestamp: data.timestamp || Date.now(),
      element: data.element
    });

    behavior.lastActivity = Date.now();
  }

  /**
   * Enregistre un événement de scroll
   * @param {string} clientId - ID du client
   * @param {object} data - { scrollY, timestamp }
   */
  recordScroll(clientId, data) {
    const behavior = this.clientBehavior.get(clientId);
    if (!behavior) return;

    behavior.scrollEvents.push({
      scrollY: data.scrollY,
      timestamp: data.timestamp || Date.now()
    });

    behavior.lastActivity = Date.now();
  }

  /**
   * Enregistre une interaction avec un formulaire
   * @param {string} clientId - ID du client
   * @param {object} data - { field, action, timestamp }
   */
  recordFormInteraction(clientId, data) {
    const behavior = this.clientBehavior.get(clientId);
    if (!behavior) return;

    behavior.formInteractions.push({
      field: data.field,
      action: data.action, // focus, blur, change
      timestamp: data.timestamp || Date.now()
    });

    behavior.lastActivity = Date.now();
  }

  /**
   * Analyse les mouvements de souris
   * @param {Array} movements - Liste des mouvements
   * @returns {object} - Résultat de l'analyse
   */
  analyzeMouseDynamics(movements) {
    if (movements.length < 2) {
      return { score: 0, reason: 'insufficient_data' };
    }

    let totalDistance = 0;
    let totalTime = 0;
    const speeds = [];
    const angles = [];

    for (let i = 1; i < movements.length; i++) {
      const prev = movements[i - 1];
      const curr = movements[i];

      const dx = curr.x - prev.x;
      const dy = curr.y - prev.y;
      const distance = Math.sqrt(dx * dx + dy * dy);
      const time = curr.timestamp - prev.timestamp;

      if (time > 0) {
        totalDistance += distance;
        totalTime += time;
        speeds.push(distance / time);
        angles.push(Math.atan2(dy, dx));
      }
    }

    const avgSpeed = totalDistance / totalTime;
    
    // Calculer la variance des vitesses (les humains ont une variance plus élevée)
    const speedVariance = this.calculateVariance(speeds);
    
    // Calculer la variance des angles (les humains ont des mouvements plus variés)
    const angleVariance = this.calculateVariance(angles);

    let score = 50;

    // Vitesse moyenne raisonnable
    if (avgSpeed >= this.thresholds.minMouseSpeed && avgSpeed <= this.thresholds.maxMouseSpeed) {
      score += 15;
    } else {
      score -= 20;
    }

    // Variance de vitesse (les bots ont souvent une vitesse constante)
    if (speedVariance > 0.5) {
      score += 15;
    } else if (speedVariance < 0.1) {
      score -= 15;
    }

    // Variance d'angle (les bots ont souvent des mouvements linéaires)
    if (angleVariance > 0.5) {
      score += 10;
    } else if (angleVariance < 0.1) {
      score -= 10;
    }

    return {
      score: Math.max(0, Math.min(100, score)),
      avgSpeed,
      speedVariance,
      angleVariance,
      movementCount: movements.length
    };
  }

  /**
   * Analyse la vitesse de frappe
   * @param {Array} keystrokes - Liste des frappes
   * @returns {object} - Résultat de l'analyse
   */
  analyzeTypingSpeed(keystrokes) {
    if (keystrokes.length < 2) {
      return { score: 0, reason: 'insufficient_data' };
    }

    const intervals = [];
    for (let i = 1; i < keystrokes.length; i++) {
      const interval = keystrokes[i].timestamp - keystrokes[i - 1].timestamp;
      if (interval > 0 && interval < 5000) { // Ignorer les pauses > 5s
        intervals.push(interval);
      }
    }

    if (intervals.length === 0) {
      return { score: 50, reason: 'no_valid_intervals' };
    }

    const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    const variance = this.calculateVariance(intervals);

    let score = 50;

    // Vitesse de frappe humaine typique
    if (avgInterval >= this.thresholds.humanTypingSpeedMin && 
        avgInterval <= this.thresholds.humanTypingSpeedMax) {
      score += 20;
    } else if (avgInterval < this.thresholds.humanTypingSpeedMin) {
      // Trop rapide = probablement un bot ou copier/coller
      score -= 30;
    }

    // Les humains ont une variance dans leur vitesse de frappe
    if (variance > 1000) {
      score += 15;
    } else if (variance < 100) {
      score -= 15;
    }

    return {
      score: Math.max(0, Math.min(100, score)),
      avgInterval,
      variance,
      keystrokeCount: keystrokes.length
    };
  }

  /**
   * Analyse complète du comportement d'un client
   * @param {string} clientId - ID du client
   * @returns {object} - Résultat de l'analyse
   */
  analyze(clientId) {
    const behavior = this.clientBehavior.get(clientId);
    if (!behavior) {
      return {
        clientId,
        score: 0,
        isHuman: false,
        reason: 'no_behavior_data'
      };
    }

    const now = Date.now();
    const timeOnPage = now - behavior.startTime;
    const flags = [];
    let totalScore = 0;
    let scoreCount = 0;

    // 1. Analyse du temps sur la page
    if (timeOnPage < this.thresholds.minTimeOnPage) {
      flags.push('too_fast');
      totalScore += 20;
    } else if (timeOnPage > this.thresholds.maxTimeOnPage) {
      flags.push('too_slow');
      totalScore += 40;
    } else {
      totalScore += 70;
    }
    scoreCount++;

    // 2. Analyse des mouvements de souris
    const mouseAnalysis = this.analyzeMouseDynamics(behavior.mouseMovements);
    if (behavior.mouseMovements.length >= this.thresholds.minMouseMovements) {
      totalScore += mouseAnalysis.score;
      scoreCount++;
    } else {
      flags.push('no_mouse_movement');
      totalScore += 30;
      scoreCount++;
    }

    // 3. Analyse de la vitesse de frappe
    const typingAnalysis = this.analyzeTypingSpeed(behavior.keystrokes);
    if (behavior.keystrokes.length >= this.thresholds.minKeystrokes) {
      totalScore += typingAnalysis.score;
      scoreCount++;
    } else {
      flags.push('no_keystrokes');
      totalScore += 40;
      scoreCount++;
    }

    // 4. Vérification des clics
    if (behavior.clicks.length === 0) {
      flags.push('no_clicks');
    }

    // 5. Vérification du scroll
    if (behavior.scrollEvents.length < this.thresholds.minScrollEvents) {
      flags.push('no_scroll');
    }

    // Calculer le score final
    const finalScore = scoreCount > 0 ? Math.round(totalScore / scoreCount) : 0;
    
    // Mettre à jour le score du client
    behavior.score = finalScore;
    behavior.flags = flags;

    const result = {
      clientId,
      score: finalScore,
      isHuman: finalScore >= this.humanScoreThreshold,
      flags,
      details: {
        timeOnPage,
        mouseMovements: behavior.mouseMovements.length,
        keystrokes: behavior.keystrokes.length,
        clicks: behavior.clicks.length,
        scrollEvents: behavior.scrollEvents.length,
        mouseAnalysis,
        typingAnalysis
      }
    };

    console.log(`[BehaviorAnalysis] 📊 Client ${clientId}: score=${finalScore}, isHuman=${result.isHuman}, flags=[${flags.join(', ')}]`);

    return result;
  }

  /**
   * Calcule la variance d'un tableau de nombres
   */
  calculateVariance(arr) {
    if (arr.length === 0) return 0;
    const mean = arr.reduce((a, b) => a + b, 0) / arr.length;
    return arr.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / arr.length;
  }

  /**
   * Supprime les données d'un client
   * @param {string} clientId - ID du client
   */
  removeClient(clientId) {
    this.clientBehavior.delete(clientId);
    console.log(`[BehaviorAnalysis] 🗑️ Client ${clientId} removed`);
  }

  /**
   * Nettoie les clients inactifs
   * @param {number} maxInactivity - Temps d'inactivité max en ms (défaut: 30 min)
   */
  cleanup(maxInactivity = 30 * 60 * 1000) {
    const now = Date.now();
    let removed = 0;

    for (const [clientId, behavior] of this.clientBehavior) {
      if (now - behavior.lastActivity > maxInactivity) {
        this.clientBehavior.delete(clientId);
        removed++;
      }
    }

    console.log(`[BehaviorAnalysis] 🧹 Cleanup: removed ${removed} inactive clients. Active: ${this.clientBehavior.size}`);
  }

  /**
   * Obtient les statistiques globales
   */
  getStats() {
    let totalScore = 0;
    let humanCount = 0;
    let botCount = 0;

    for (const [, behavior] of this.clientBehavior) {
      totalScore += behavior.score;
      if (behavior.score >= this.humanScoreThreshold) {
        humanCount++;
      } else {
        botCount++;
      }
    }

    return {
      activeClients: this.clientBehavior.size,
      avgScore: this.clientBehavior.size > 0 ? Math.round(totalScore / this.clientBehavior.size) : 0,
      humanCount,
      botCount
    };
  }
}

module.exports = BehaviorAnalysis;
