// Configuration WebSocket pour la production
// Ce fichier configure l'URL du serveur WebSocket
(function() {
  window.CONFIG = window.CONFIG || {};
  window.CONFIG.WS_URL = 'wss://neti-websocket-server.onrender.com';
  console.log('[config.js] WebSocket URL configured:', window.CONFIG.WS_URL);
})();
