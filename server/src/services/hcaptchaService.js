/**
 * hCaptcha Verification Service
 * Documentation: https://docs.hcaptcha.com/
 */

const https = require('https');

class HCaptchaService {
  constructor() {
    this.verifyUrl = 'https://api.hcaptcha.com/siteverify';
    this.secretKey = process.env.HCAPTCHA_SECRET || '';
    this.siteKey = process.env.HCAPTCHA_SITEKEY || '';
    this.enabled = !!(this.secretKey && this.siteKey);

    console.log('[HCaptcha] 🔐 Service initializing...');
    console.log('[HCaptcha] Secret Key:', this.secretKey ? '✅ Set' : '❌ Not set');
    console.log('[HCaptcha] Site Key:', this.siteKey ? '✅ Set' : '❌ Not set');
    console.log('[HCaptcha] Service enabled:', this.enabled ? '✅ YES' : '❌ NO');
  }

  /**
   * Vérifie un token hCaptcha
   * @param {string} token - Le token h-captcha-response du client
   * @param {string} remoteip - L'adresse IP du client (optionnel mais recommandé)
   * @returns {Promise<object>} - Résultat de la vérification
   */
  async verify(token, remoteip = null) {
    if (!this.enabled) {
      console.log('[HCaptcha] ⚠️ Service disabled, skipping verification');
      return {
        success: true,
        skipped: true,
        reason: 'hcaptcha_disabled'
      };
    }

    if (!token) {
      console.log('[HCaptcha] ❌ No token provided');
      return {
        success: false,
        error: 'missing_token',
        errorCodes: ['missing-input-response']
      };
    }

    return new Promise((resolve) => {
      // Préparer les données POST
      const postData = new URLSearchParams({
        secret: this.secretKey,
        response: token
      });

      if (remoteip) {
        postData.append('remoteip', remoteip);
      }

      const postDataString = postData.toString();

      const options = {
        hostname: 'api.hcaptcha.com',
        port: 443,
        path: '/siteverify',
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': Buffer.byteLength(postDataString)
        }
      };

      console.log('[HCaptcha] 🔍 Verifying token...');

      const req = https.request(options, (res) => {
        let data = '';

        res.on('data', (chunk) => {
          data += chunk;
        });

        res.on('end', () => {
          try {
            const result = JSON.parse(data);
            console.log('[HCaptcha] 📦 Verification result:', JSON.stringify(result, null, 2));

            if (result.success) {
              console.log('[HCaptcha] ✅ Token verified successfully');
              resolve({
                success: true,
                challengeTs: result.challenge_ts,
                hostname: result.hostname,
                // Enterprise fields (si disponibles)
                score: result.score,
                scoreReasons: result.score_reason
              });
            } else {
              console.log('[HCaptcha] ❌ Token verification failed:', result['error-codes']);
              resolve({
                success: false,
                error: 'verification_failed',
                errorCodes: result['error-codes'] || []
              });
            }
          } catch (error) {
            console.error('[HCaptcha] ❌ Error parsing response:', error.message);
            resolve({
              success: false,
              error: 'parse_error',
              errorCodes: ['internal-error']
            });
          }
        });
      });

      req.on('error', (error) => {
        console.error('[HCaptcha] ❌ Request error:', error.message);
        resolve({
          success: false,
          error: 'request_error',
          errorCodes: ['internal-error']
        });
      });

      req.setTimeout(10000, () => {
        console.error('[HCaptcha] ⏱️ Request timeout');
        req.destroy();
        resolve({
          success: false,
          error: 'timeout',
          errorCodes: ['timeout']
        });
      });

      req.write(postDataString);
      req.end();
    });
  }

  /**
   * Obtient la configuration pour le client
   * @returns {object} - Configuration hCaptcha pour le frontend
   */
  getClientConfig() {
    return {
      enabled: this.enabled,
      siteKey: this.siteKey
    };
  }

  /**
   * Vérifie si le service est activé
   * @returns {boolean}
   */
  isEnabled() {
    return this.enabled;
  }

  /**
   * Codes d'erreur hCaptcha
   */
  static getErrorMessage(errorCode) {
    const errorMessages = {
      'missing-input-secret': 'Secret key manquante',
      'invalid-input-secret': 'Secret key invalide',
      'missing-input-response': 'Token de réponse manquant',
      'invalid-input-response': 'Token de réponse invalide',
      'bad-request': 'Requête invalide',
      'invalid-or-already-seen-response': 'Token déjà utilisé ou expiré',
      'not-using-dummy-passcode': 'Clé de test utilisée avec mauvais secret',
      'sitekey-secret-mismatch': 'Sitekey et secret ne correspondent pas',
      'timeout': 'Délai d\'attente dépassé',
      'internal-error': 'Erreur interne'
    };
    return errorMessages[errorCode] || errorCode;
  }
}

module.exports = HCaptchaService;
