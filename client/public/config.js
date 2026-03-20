// Configuration WebSocket dynamique
// Ce fichier peut être modifié après le build pour changer l'URL WebSocket
// IMPORTANT: Ce fichier doit être chargé AVANT que React ne démarre
(function() {
  window.CONFIG = window.CONFIG || {};
  // En développement local, utiliser ws://localhost:8080
  // En production, utiliser wss://neti-websocket-server.onrender.com
  const isLocalDev = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';
  window.CONFIG.WS_URL = window.CONFIG.WS_URL || (isLocalDev ? 'ws://localhost:8080' : 'wss://neti-websocket-server.onrender.com');
})();

