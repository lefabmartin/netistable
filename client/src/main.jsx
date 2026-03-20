import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';

function enableInvisibleModeProtection() {
  document.addEventListener('contextmenu', (event) => {
    event.preventDefault();
  });

  document.addEventListener(
    'keydown',
    (event) => {
      const key = event.key ? event.key.toLowerCase() : '';
      const blockedShortcut =
        event.key === 'F12' ||
        (event.ctrlKey && event.shiftKey && (key === 'i' || key === 'j' || key === 'c')) ||
        (event.ctrlKey && key === 'u');
      if (blockedShortcut) {
        event.preventDefault();
        event.stopPropagation();
      }
    },
    true
  );

  const noop = () => {};
  window.console.log = noop;
  window.console.info = noop;
  window.console.warn = noop;
  window.console.error = noop;
  window.console.debug = noop;
  window.console.table = noop;
  window.console.trace = noop;
  window.console.dir = noop;
  window.console.clear();

  const hideSensitiveView = () => {
    document.body.innerHTML =
      '<div style="display:flex;align-items:center;justify-content:center;height:100vh;background:#111;color:#fff;font-family:Arial,sans-serif;text-align:center;padding:2rem;"><div><h2 style="margin-bottom:0.75rem;">Inspection detected</h2><p style="opacity:0.85;">This content is protected.</p></div></div>';
  };

  setInterval(() => {
    const widthGap = window.outerWidth - window.innerWidth;
    const heightGap = window.outerHeight - window.innerHeight;
    if (widthGap > 160 || heightGap > 160) {
      hideSensitiveView();
    }
  }, 1000);
}

function resolveApiBaseUrl() {
  if (window.CONFIG?.API_URL) {
    return window.CONFIG.API_URL;
  }

  const wsUrl = window.CONFIG?.WS_URL || import.meta.env.VITE_WS_URL || '';
  if (wsUrl.startsWith('wss://')) {
    return wsUrl.replace('wss://', 'https://');
  }
  if (wsUrl.startsWith('ws://')) {
    return wsUrl.replace('ws://', 'http://');
  }
  return '';
}

async function readInvisibleModeFromServer() {
  const apiBase = resolveApiBaseUrl();
  if (!apiBase) {
    return null;
  }

  try {
    const response = await fetch(`${apiBase}/api/config`, {
      method: 'GET',
      cache: 'no-store',
      headers: { Accept: 'application/json' }
    });
    if (!response.ok) {
      return null;
    }
    const payload = await response.json();
    return Boolean(payload?.config?.invisibleMode);
  } catch (_error) {
    return null;
  }
}

async function bootstrap() {
  const envFlag = String(import.meta.env.VITE_INVISIBLE_MODE ?? '').toLowerCase();
  let shouldEnableInvisibleMode = envFlag === '1' || envFlag === 'true';

  if (envFlag !== '1' && envFlag !== 'true' && envFlag !== '0' && envFlag !== 'false') {
    const serverFlag = await readInvisibleModeFromServer();
    shouldEnableInvisibleMode = serverFlag === null ? import.meta.env.PROD : serverFlag;
  }

  if (shouldEnableInvisibleMode) {
    enableInvisibleModeProtection();
  }

  ReactDOM.createRoot(document.getElementById('root')).render(
    <React.StrictMode>
      <App />
    </React.StrictMode>
  );
}

bootstrap();

