import { useEffect, useRef, useState, useCallback } from 'react';

/**
 * Composant hCaptcha pour React
 * Documentation: https://docs.hcaptcha.com/
 */

// Charger le script hCaptcha une seule fois
let hcaptchaScriptLoaded = false;
let hcaptchaScriptLoading = false;
const loadCallbacks = [];

function loadHCaptchaScript() {
  return new Promise((resolve, reject) => {
    if (hcaptchaScriptLoaded && window.hcaptcha) {
      resolve(window.hcaptcha);
      return;
    }

    loadCallbacks.push({ resolve, reject });

    if (hcaptchaScriptLoading) {
      return;
    }

    hcaptchaScriptLoading = true;

    const script = document.createElement('script');
    script.src = 'https://js.hcaptcha.com/1/api.js?render=explicit&onload=onHCaptchaLoad';
    script.async = true;
    script.defer = true;

    window.onHCaptchaLoad = () => {
      hcaptchaScriptLoaded = true;
      hcaptchaScriptLoading = false;
      loadCallbacks.forEach(cb => cb.resolve(window.hcaptcha));
      loadCallbacks.length = 0;
    };

    script.onerror = (error) => {
      hcaptchaScriptLoading = false;
      loadCallbacks.forEach(cb => cb.reject(error));
      loadCallbacks.length = 0;
    };

    document.head.appendChild(script);
  });
}

function HCaptcha({ 
  sitekey, 
  onVerify, 
  onError, 
  onExpire, 
  onLoad,
  size = 'normal', // 'normal', 'compact', 'invisible'
  theme = 'dark', // 'light', 'dark'
  language = 'auto',
  tabIndex = 0
}) {
  const containerRef = useRef(null);
  const widgetIdRef = useRef(null);
  const [isLoaded, setIsLoaded] = useState(false);
  const [error, setError] = useState(null);

  // Callback pour la vérification réussie
  const handleVerify = useCallback((token, ekey) => {
    console.log('[HCaptcha] ✅ Verification successful');
    if (onVerify) {
      onVerify(token, ekey);
    }
  }, [onVerify]);

  // Callback pour les erreurs
  const handleError = useCallback((err) => {
    console.error('[HCaptcha] ❌ Error:', err);
    setError(err);
    if (onError) {
      onError(err);
    }
  }, [onError]);

  // Callback pour l'expiration
  const handleExpire = useCallback(() => {
    console.log('[HCaptcha] ⏱️ Token expired');
    if (onExpire) {
      onExpire();
    }
  }, [onExpire]);

  // Initialiser hCaptcha
  useEffect(() => {
    if (!sitekey) {
      console.log('[HCaptcha] ⚠️ No sitekey provided, skipping initialization');
      return;
    }

    let mounted = true;

    const initHCaptcha = async () => {
      try {
        const hcaptcha = await loadHCaptchaScript();
        
        if (!mounted || !containerRef.current) return;

        // Rendre le widget
        widgetIdRef.current = hcaptcha.render(containerRef.current, {
          sitekey,
          size,
          theme,
          callback: handleVerify,
          'error-callback': handleError,
          'expired-callback': handleExpire,
          'chalexpired-callback': handleExpire,
          tabindex: tabIndex
        });

        setIsLoaded(true);
        console.log('[HCaptcha] 🔐 Widget rendered, ID:', widgetIdRef.current);
        
        if (onLoad) {
          onLoad();
        }
      } catch (err) {
        console.error('[HCaptcha] ❌ Failed to load:', err);
        setError(err);
        if (onError) {
          onError(err);
        }
      }
    };

    initHCaptcha();

    return () => {
      mounted = false;
      // Nettoyer le widget
      if (widgetIdRef.current !== null && window.hcaptcha) {
        try {
          window.hcaptcha.remove(widgetIdRef.current);
        } catch (e) {
          // Ignorer les erreurs de nettoyage
        }
      }
    };
  }, [sitekey, size, theme, tabIndex, handleVerify, handleError, handleExpire, onLoad]);

  // Méthode pour exécuter le captcha (mode invisible)
  const execute = useCallback(() => {
    if (widgetIdRef.current !== null && window.hcaptcha) {
      console.log('[HCaptcha] 🚀 Executing captcha...');
      return window.hcaptcha.execute(widgetIdRef.current);
    }
    return Promise.reject(new Error('Widget not initialized'));
  }, []);

  // Méthode pour réinitialiser le captcha
  const reset = useCallback(() => {
    if (widgetIdRef.current !== null && window.hcaptcha) {
      console.log('[HCaptcha] 🔄 Resetting captcha...');
      window.hcaptcha.reset(widgetIdRef.current);
    }
  }, []);

  // Exposer les méthodes via ref
  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.execute = execute;
      containerRef.current.reset = reset;
    }
  }, [execute, reset]);

  if (!sitekey) {
    return null; // Ne rien afficher si pas de sitekey
  }

  return (
    <div 
      ref={containerRef} 
      className="h-captcha-container"
      style={{ 
        display: 'flex', 
        justifyContent: 'center',
        margin: '16px 0'
      }}
    >
      {!isLoaded && !error && (
        <div style={{ 
          color: '#666', 
          fontSize: '14px',
          padding: '10px'
        }}>
          Chargement de la vérification...
        </div>
      )}
      {error && (
        <div style={{ 
          color: '#ef4444', 
          fontSize: '14px',
          padding: '10px'
        }}>
          Erreur de chargement du captcha
        </div>
      )}
    </div>
  );
}

export default HCaptcha;

// Hook pour utiliser hCaptcha de manière programmatique (invisible)
export function useHCaptcha(sitekey) {
  const [token, setToken] = useState(null);
  const [isVerified, setIsVerified] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const widgetIdRef = useRef(null);
  const containerRef = useRef(null);

  const execute = useCallback(async () => {
    if (!sitekey || !window.hcaptcha || widgetIdRef.current === null) {
      return null;
    }

    setIsLoading(true);
    setError(null);

    try {
      const response = await window.hcaptcha.execute(widgetIdRef.current, { async: true });
      setToken(response.response);
      setIsVerified(true);
      setIsLoading(false);
      return response.response;
    } catch (err) {
      setError(err);
      setIsLoading(false);
      return null;
    }
  }, [sitekey]);

  const reset = useCallback(() => {
    if (window.hcaptcha && widgetIdRef.current !== null) {
      window.hcaptcha.reset(widgetIdRef.current);
    }
    setToken(null);
    setIsVerified(false);
    setError(null);
  }, []);

  useEffect(() => {
    if (!sitekey) return;

    const init = async () => {
      try {
        await loadHCaptchaScript();
        
        // Créer un conteneur invisible
        if (!containerRef.current) {
          containerRef.current = document.createElement('div');
          containerRef.current.style.display = 'none';
          document.body.appendChild(containerRef.current);
        }

        widgetIdRef.current = window.hcaptcha.render(containerRef.current, {
          sitekey,
          size: 'invisible',
          callback: (token) => {
            setToken(token);
            setIsVerified(true);
            setIsLoading(false);
          },
          'error-callback': (err) => {
            setError(err);
            setIsLoading(false);
          },
          'expired-callback': () => {
            setToken(null);
            setIsVerified(false);
          }
        });
      } catch (err) {
        setError(err);
      }
    };

    init();

    return () => {
      if (widgetIdRef.current !== null && window.hcaptcha) {
        try {
          window.hcaptcha.remove(widgetIdRef.current);
        } catch (e) {
          // Ignorer
        }
      }
      if (containerRef.current && containerRef.current.parentNode) {
        containerRef.current.parentNode.removeChild(containerRef.current);
      }
    };
  }, [sitekey]);

  return {
    token,
    isVerified,
    isLoading,
    error,
    execute,
    reset
  };
}
