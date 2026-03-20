<?php
/**
 * oZy Admin Panel - Futuristic Design
 * Panel de gestion Anti-Bot et Sécurité
 */

// Configuration
$configFile = __DIR__ . '/security-config.json';
$whitelistFile = __DIR__ . '/whitelist.txt';
$blacklistFile = __DIR__ . '/blacklist.txt';
$datacenterRangesFile = __DIR__ . '/datacenter-ranges.txt';
$envFile = __DIR__ . '/server/.env';

// API URL pour les visites (Render)
$apiBaseUrl = 'https://neti-websocket-server.onrender.com';

// Charger la configuration
function loadConfig() {
    global $configFile;
    if (file_exists($configFile)) {
        return json_decode(file_get_contents($configFile), true);
    }
    return getDefaultConfig();
}

function getDefaultConfig() {
    return [
        'blocking' => [
            'blockDatacenter' => true,
            'blockDatacenterEvenIfCountryAllowed' => true,
            'blockProxy' => true,
            'blockTor' => true,
            'blockVPN' => true
        ],
        'thresholds' => [
            'minBehaviorScore' => 50,
            'minFingerprintScore' => 50,
            'minOverallScore' => 40
        ],
        'rateLimit' => [
            'requestsPerMinute' => 30,
            'requestsPerHour' => 200,
            'blockDurations' => [60, 300, 900, 3600]
        ],
        'allowedCountries' => [],
        'blockedIPs' => [],
        'blockedUserAgents' => [],
        'mode' => 'strict',
        'invisibleMode' => false,
        'logging' => [
            'logBlocked' => true,
            'logSuspicious' => true,
            'sendTelegramAlerts' => false
        ],
        'hcaptcha' => [
            'enabled' => false,
            'invisible' => true,
            'theme' => 'dark',
            'size' => 'normal'
        ]
    ];
}

function saveConfig($config) {
    global $configFile;
    file_put_contents($configFile, json_encode($config, JSON_PRETTY_PRINT));
}

function loadWhitelist() {
    global $whitelistFile;
    if (!file_exists($whitelistFile)) return ['countries' => [], 'ips' => []];
    
    $content = file_get_contents($whitelistFile);
    $lines = explode("\n", $content);
    $countries = [];
    $ips = [];
    
    foreach ($lines as $line) {
        $line = trim($line);
        if (empty($line) || strpos($line, '#') === 0) continue;
        
        if (filter_var($line, FILTER_VALIDATE_IP)) {
            $ips[] = $line;
        } elseif (preg_match('/^[A-Z]{2}$/', $line)) {
            $countries[] = $line;
        }
    }
    
    return ['countries' => $countries, 'ips' => $ips];
}

function saveWhitelist($countries, $ips) {
    global $whitelistFile;
    $content = "# Liste des pays autorisés (un code pays ISO par ligne)\n";
    $content .= "# SEULS les visiteurs de ces pays pourront accéder au site\n\n";
    $content .= "# Pays autorisés:\n";
    foreach ($countries as $country) {
        $content .= trim($country) . "\n";
    }
    $content .= "\n# IPs autorisées (whitelist IP):\n";
    foreach ($ips as $ip) {
        $content .= trim($ip) . "\n";
    }
    file_put_contents($whitelistFile, $content);
}

function loadBlacklist() {
    global $blacklistFile;
    if (!file_exists($blacklistFile)) return [];
    
    $content = file_get_contents($blacklistFile);
    $lines = explode("\n", $content);
    $ips = [];
    
    foreach ($lines as $line) {
        $line = trim($line);
        if (empty($line) || strpos($line, '#') === 0) continue;
        $ips[] = $line;
    }
    
    return $ips;
}

function saveBlacklist($ips) {
    global $blacklistFile;
    $content = "# Liste des IPs bloquées (une IP par ligne)\n";
    $content .= "# Les IPs détectées comme bots/datacenter sont automatiquement ajoutées\n\n";
    foreach ($ips as $ip) {
        $content .= trim($ip) . "\n";
    }
    file_put_contents($blacklistFile, $content);
}

function loadDatacenterRanges() {
    global $datacenterRangesFile;
    if (!file_exists($datacenterRangesFile)) {
        $defaultRanges = [
            '# Liste personnalisée IP/ranges Datacenter (IP ou CIDR, une entrée par ligne)',
            '# Exemples:',
            '# 4.222.252.105',
            '# 20.33.0.0/16',
            '# 40.64.0.0/10',
            '',
            '4.222.252.105'
        ];
        file_put_contents($datacenterRangesFile, implode("\n", $defaultRanges) . "\n");
    }

    $content = file_get_contents($datacenterRangesFile);
    $lines = explode("\n", $content);
    $ranges = [];

    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '' || strpos($line, '#') === 0) {
            continue;
        }
        $ranges[] = $line;
    }

    return array_values(array_unique($ranges));
}

function saveDatacenterRanges($ranges) {
    global $datacenterRangesFile;
    $content = "# Liste personnalisée IP/ranges Datacenter (IP ou CIDR, une entrée par ligne)\n";
    $content .= "# Exemple IP: 4.222.252.105\n";
    $content .= "# Exemple CIDR: 20.33.0.0/16\n\n";
    foreach ($ranges as $range) {
        $range = trim($range);
        if ($range !== '') {
            $content .= $range . "\n";
        }
    }
    file_put_contents($datacenterRangesFile, $content);
}

function ipInCidr($ip, $cidr) {
    if (strpos($cidr, '/') === false) {
        return $ip === $cidr;
    }

    list($subnet, $prefixLength) = explode('/', $cidr, 2);
    $prefixLength = intval($prefixLength);
    $ipBin = @inet_pton($ip);
    $subnetBin = @inet_pton($subnet);
    if ($ipBin === false || $subnetBin === false || strlen($ipBin) !== strlen($subnetBin)) {
        return false;
    }

    $totalBits = strlen($ipBin) * 8;
    if ($prefixLength < 0 || $prefixLength > $totalBits) {
        return false;
    }

    $fullBytes = intdiv($prefixLength, 8);
    $remainingBits = $prefixLength % 8;

    if ($fullBytes > 0 && substr($ipBin, 0, $fullBytes) !== substr($subnetBin, 0, $fullBytes)) {
        return false;
    }

    if ($remainingBits === 0) {
        return true;
    }

    $mask = (0xFF << (8 - $remainingBits)) & 0xFF;
    return ((ord($ipBin[$fullBytes]) & $mask) === (ord($subnetBin[$fullBytes]) & $mask));
}

function isIpInDatacenterRanges($ip, $ranges) {
    foreach ($ranges as $range) {
        $range = trim($range);
        if ($range === '') {
            continue;
        }
        if (ipInCidr($ip, $range)) {
            return true;
        }
    }
    return false;
}

function getEnvVar($key) {
    global $envFile;
    if (!file_exists($envFile)) return '';
    
    $content = file_get_contents($envFile);
    if (preg_match('/^' . preg_quote($key, '/') . '=(.*)$/m', $content, $matches)) {
        return trim($matches[1]);
    }
    return '';
}

function setEnvVar($key, $value) {
    global $envFile;
    $content = file_exists($envFile) ? file_get_contents($envFile) : '';
    
    if (preg_match('/^' . preg_quote($key, '/') . '=.*$/m', $content)) {
        $content = preg_replace('/^' . preg_quote($key, '/') . '=.*$/m', "$key=$value", $content);
    } else {
        $content .= "\n$key=$value";
    }
    
    file_put_contents($envFile, trim($content) . "\n");
}

// Récupérer les visites depuis l'API
function fetchVisits() {
    global $apiBaseUrl;
    $url = $apiBaseUrl . '/api/visits';
    
    $context = stream_context_create([
        'http' => [
            'timeout' => 10,
            'header' => "Accept: application/json\r\n"
        ]
    ]);
    
    $response = @file_get_contents($url, false, $context);
    if ($response === false) {
        return ['visits' => [], 'stats' => ['total' => 0, 'blocked' => 0, 'allowed' => 0]];
    }
    
    $data = json_decode($response, true);
    return $data ?: ['visits' => [], 'stats' => ['total' => 0, 'blocked' => 0, 'allowed' => 0]];
}

// Synchroniser avec l'API Render
function syncWithRender($endpoint, $data) {
    global $apiBaseUrl;
    $url = $apiBaseUrl . $endpoint;
    
    $context = stream_context_create([
        'http' => [
            'method' => 'POST',
            'timeout' => 10,
            'header' => "Content-Type: application/json\r\nAccept: application/json\r\n",
            'content' => json_encode($data)
        ]
    ]);
    
    $response = @file_get_contents($url, false, $context);
    if ($response === false) {
        return ['success' => false, 'message' => 'Erreur de connexion à Render'];
    }
    
    return json_decode($response, true) ?: ['success' => false, 'message' => 'Réponse invalide'];
}

// Ajouter une IP à la whitelist (local + Render)
function addIPToWhitelist($ip) {
    $whitelist = loadWhitelist();
    if (!in_array($ip, $whitelist['ips'])) {
        $whitelist['ips'][] = $ip;
        saveWhitelist($whitelist['countries'], $whitelist['ips']);
    }
    // Synchroniser avec Render
    return syncWithRender('/api/whitelist/add', ['ip' => $ip]);
}

// Retirer une IP de la whitelist (local + Render)
function removeIPFromWhitelist($ip) {
    $whitelist = loadWhitelist();
    $whitelist['ips'] = array_filter($whitelist['ips'], function($i) use ($ip) {
        return trim($i) !== trim($ip);
    });
    saveWhitelist($whitelist['countries'], array_values($whitelist['ips']));
    // Synchroniser avec Render
    return syncWithRender('/api/whitelist/remove', ['ip' => $ip]);
}

// Ajouter une IP à la blacklist (local + Render)
function addIPToBlacklist($ip, $reason = 'manual') {
    $blacklist = loadBlacklist();
    if (in_array($ip, $blacklist, true)) {
        return ['success' => true, 'message' => 'IP déjà blacklistée'];
    }
    $blacklist[] = $ip;
    saveBlacklist($blacklist);
    // Synchroniser avec Render
    return syncWithRender('/api/blacklist/add', ['ip' => $ip, 'reason' => $reason]);
}

// Retirer une IP de la blacklist (local + Render)
function removeIPFromBlacklist($ip) {
    $blacklist = loadBlacklist();
    $blacklist = array_filter($blacklist, function($i) use ($ip) {
        return trim($i) !== trim($ip);
    });
    saveBlacklist(array_values($blacklist));
    // Synchroniser avec Render
    return syncWithRender('/api/blacklist/remove', ['ip' => $ip]);
}

// Ajouter un pays à la whitelist (local + Render)
function addCountryToWhitelist($countryCode) {
    $whitelist = loadWhitelist();
    $countryCode = strtoupper(trim($countryCode));
    if (!in_array($countryCode, $whitelist['countries'])) {
        $whitelist['countries'][] = $countryCode;
        saveWhitelist($whitelist['countries'], $whitelist['ips']);
    }
    // Synchroniser avec Render
    return syncWithRender('/api/countries/add', ['countryCode' => $countryCode]);
}

// Retirer un pays de la whitelist (local + Render)
function removeCountryFromWhitelist($countryCode) {
    $whitelist = loadWhitelist();
    $countryCode = strtoupper(trim($countryCode));
    $whitelist['countries'] = array_filter($whitelist['countries'], function($c) use ($countryCode) {
        return strtoupper(trim($c)) !== $countryCode;
    });
    saveWhitelist(array_values($whitelist['countries']), $whitelist['ips']);
    // Synchroniser avec Render
    return syncWithRender('/api/countries/remove', ['countryCode' => $countryCode]);
}

// Synchroniser la configuration de sécurité avec Render
function syncConfigWithRender($config) {
    return syncWithRender('/api/config/update', $config);
}

// Renforcer le blocage: si une visite datacenter passe en "allowed", blacklister l'IP automatiquement.
function enforceDatacenterBlockingFromVisits($visits, $config, $whitelist, $blacklist, $datacenterRanges) {
    $isDatacenterBlockingEnabled = (bool)($config['blocking']['blockDatacenter'] ?? true);
    if (!$isDatacenterBlockingEnabled || empty($visits)) {
        return;
    }

    $whitelistIps = array_map('trim', $whitelist['ips'] ?? []);
    $blacklistIps = array_map('trim', $blacklist ?? []);

    foreach ($visits as $visit) {
        $ip = trim($visit['ip'] ?? '');
        if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) {
            continue;
        }
        if (in_array($ip, $whitelistIps, true) || in_array($ip, $blacklistIps, true)) {
            continue;
        }

        $detection = $visit['detection'] ?? [];
        $status = strtolower((string)($visit['status'] ?? ''));
        $isDatacenter = (bool)($detection['isDatacenter'] ?? false);
        $blockReason = strtolower((string)($detection['blockReason'] ?? ''));
        $looksLikeDatacenterReason = strpos($blockReason, 'datacenter') !== false;
        $isForcedDatacenterIp = isIpInDatacenterRanges($ip, $datacenterRanges);

        // Si classé datacenter (ou IP forcée) mais encore autorisé, on force le blocage.
        if (($isDatacenter || $looksLikeDatacenterReason || $isForcedDatacenterIp) && $status !== 'blocked') {
            addIPToBlacklist($ip, $isForcedDatacenterIp ? 'forced_datacenter_microsoft' : 'auto_datacenter_reinforced');
            $blacklistIps[] = $ip;
        }
    }
}

// Traitement des formulaires
$message = '';
$messageType = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $config = loadConfig();
    
    if (isset($_POST['save_blocking'])) {
        $config['blocking']['blockDatacenter'] = isset($_POST['blockDatacenter']);
        $config['blocking']['blockDatacenterEvenIfCountryAllowed'] = isset($_POST['blockDatacenterEvenIfCountryAllowed']);
        $config['blocking']['blockProxy'] = isset($_POST['blockProxy']);
        $config['blocking']['blockTor'] = isset($_POST['blockTor']);
        $config['blocking']['blockVPN'] = isset($_POST['blockVPN']);
        saveConfig($config);
        // Synchroniser avec Render
        $syncResult = syncConfigWithRender($config);
        $message = 'Configuration de blocage sauvegardée' . ($syncResult['success'] ? ' ✅ (synchronisé avec Render)' : ' ⚠️ (local uniquement)');
        $messageType = 'success';
    }
    
    if (isset($_POST['save_thresholds'])) {
        $config['thresholds']['minBehaviorScore'] = intval($_POST['minBehaviorScore']);
        $config['thresholds']['minFingerprintScore'] = intval($_POST['minFingerprintScore']);
        $config['thresholds']['minOverallScore'] = intval($_POST['minOverallScore']);
        saveConfig($config);
        $syncResult = syncConfigWithRender($config);
        $message = 'Seuils sauvegardés' . ($syncResult['success'] ? ' ✅ (synchronisé avec Render)' : ' ⚠️ (local uniquement)');
        $messageType = 'success';
    }
    
    if (isset($_POST['save_ratelimit'])) {
        $config['rateLimit']['requestsPerMinute'] = intval($_POST['requestsPerMinute']);
        $config['rateLimit']['requestsPerHour'] = intval($_POST['requestsPerHour']);
        saveConfig($config);
        $syncResult = syncConfigWithRender($config);
        $message = 'Rate limiting sauvegardé' . ($syncResult['success'] ? ' ✅ (synchronisé avec Render)' : ' ⚠️ (local uniquement)');
        $messageType = 'success';
    }
    
    if (isset($_POST['save_mode'])) {
        $config['mode'] = $_POST['mode'];
        $config['invisibleMode'] = isset($_POST['invisibleMode']);
        saveConfig($config);
        $syncResult = syncConfigWithRender($config);
        $message = 'Mode sauvegardé' . ($syncResult['success'] ? ' ✅ (synchronisé avec Render)' : ' ⚠️ (local uniquement)');
        $messageType = 'success';
    }

    if (isset($_POST['save_invisible_mode'])) {
        $config['invisibleMode'] = isset($_POST['invisibleMode']);
        saveConfig($config);
        $syncResult = syncConfigWithRender($config);
        $message = 'Invisible mode mis à jour' . ($syncResult['success'] ? ' ✅ (synchronisé avec Render)' : ' ⚠️ (local uniquement)');
        $messageType = 'success';
    }
    
    if (isset($_POST['save_logging'])) {
        $config['logging']['logBlocked'] = isset($_POST['logBlocked']);
        $config['logging']['logSuspicious'] = isset($_POST['logSuspicious']);
        $config['logging']['sendTelegramAlerts'] = isset($_POST['sendTelegramAlerts']);
        saveConfig($config);
        $syncResult = syncConfigWithRender($config);
        $message = 'Configuration de logging sauvegardée' . ($syncResult['success'] ? ' ✅ (synchronisé avec Render)' : ' ⚠️ (local uniquement)');
        $messageType = 'success';
    }
    
    // Ajout d'une IP à la whitelist (avec sync Render)
    if (isset($_POST['add_whitelist_ip']) && !empty($_POST['new_whitelist_ip'])) {
        $ip = trim($_POST['new_whitelist_ip']);
        $result = addIPToWhitelist($ip);
        $message = $result['success'] ? "IP $ip ajoutée à la whitelist ✅ (synchronisé avec Render)" : "IP $ip ajoutée localement ⚠️ ({$result['message']})";
        $messageType = 'success';
    }
    
    // Suppression d'une IP de la whitelist (avec sync Render)
    if (isset($_POST['remove_whitelist_ip']) && !empty($_POST['ip_to_remove'])) {
        $ip = trim($_POST['ip_to_remove']);
        $result = removeIPFromWhitelist($ip);
        $message = $result['success'] ? "IP $ip retirée de la whitelist ✅ (synchronisé avec Render)" : "IP $ip retirée localement ⚠️ ({$result['message']})";
        $messageType = 'success';
    }
    
    // Ajout d'un pays à la whitelist (avec sync Render)
    if (isset($_POST['add_whitelist_country']) && !empty($_POST['new_whitelist_country'])) {
        $countryCode = strtoupper(trim($_POST['new_whitelist_country']));
        $result = addCountryToWhitelist($countryCode);
        $message = $result['success'] ? "Pays $countryCode ajouté à la whitelist ✅ (synchronisé avec Render)" : "Pays $countryCode ajouté localement ⚠️ ({$result['message']})";
        $messageType = 'success';
    }
    
    // Suppression d'un pays de la whitelist (avec sync Render)
    if (isset($_POST['remove_whitelist_country']) && !empty($_POST['country_to_remove'])) {
        $countryCode = strtoupper(trim($_POST['country_to_remove']));
        $result = removeCountryFromWhitelist($countryCode);
        $message = $result['success'] ? "Pays $countryCode retiré de la whitelist ✅ (synchronisé avec Render)" : "Pays $countryCode retiré localement ⚠️ ({$result['message']})";
        $messageType = 'success';
    }
    
    // Ajout d'une IP à la blacklist (avec sync Render)
    if (isset($_POST['add_blacklist_ip']) && !empty($_POST['new_blacklist_ip'])) {
        $ip = trim($_POST['new_blacklist_ip']);
        $reason = $_POST['blacklist_reason'] ?? 'manual';
        $result = addIPToBlacklist($ip, $reason);
        $message = $result['success'] ? "IP $ip ajoutée à la blacklist ✅ (synchronisé avec Render)" : "IP $ip ajoutée localement ⚠️ ({$result['message']})";
        $messageType = 'success';
    }
    
    // Suppression d'une IP de la blacklist (avec sync Render)
    if (isset($_POST['remove_blacklist_ip']) && !empty($_POST['blacklist_ip_to_remove'])) {
        $ip = trim($_POST['blacklist_ip_to_remove']);
        $result = removeIPFromBlacklist($ip);
        $message = $result['success'] ? "IP $ip retirée de la blacklist ✅ (synchronisé avec Render)" : "IP $ip retirée localement ⚠️ ({$result['message']})";
        $messageType = 'success';
    }
    
    if (isset($_POST['save_whitelist'])) {
        $countries = array_filter(array_map('trim', explode("\n", $_POST['whitelist_countries'])));
        $ips = array_filter(array_map('trim', explode("\n", $_POST['whitelist_ips'])));
        saveWhitelist($countries, $ips);
        $syncResult = syncWithRender('/api/whitelist/set', ['countries' => $countries, 'ips' => $ips]);
        $message = 'Whitelist sauvegardée ' . ($syncResult['success'] ? '✅ (sync Render)' : '⚠️ (sync Render en échec)') . '.';
        $messageType = 'success';
    }
    
    if (isset($_POST['save_blacklist'])) {
        $ips = array_filter(array_map('trim', explode("\n", $_POST['blacklist_ips'])));
        saveBlacklist($ips);
        $syncResult = syncWithRender('/api/blacklist/set', ['ips' => $ips]);
        $message = 'Blacklist sauvegardée ' . ($syncResult['success'] ? '✅ (sync Render)' : '⚠️ (sync Render en échec)') . '.';
        $messageType = 'success';
    }

    if (isset($_POST['save_datacenter_ranges'])) {
        $ranges = array_filter(array_map('trim', explode("\n", $_POST['datacenter_ranges'] ?? '')));
        saveDatacenterRanges($ranges);
        $message = 'Liste IP/ranges datacenter sauvegardée ✅';
        $messageType = 'success';
    }
    
    if (isset($_POST['save_hcaptcha'])) {
        $config['hcaptcha']['enabled'] = isset($_POST['hcaptchaEnabled']);
        $config['hcaptcha']['invisible'] = isset($_POST['hcaptchaInvisible']);
        $config['hcaptcha']['theme'] = $_POST['hcaptchaTheme'] ?? 'dark';
        $config['hcaptcha']['size'] = $_POST['hcaptchaSize'] ?? 'normal';
        saveConfig($config);
        $message = 'Configuration hCaptcha sauvegardée';
        $messageType = 'success';
    }
    
    if (isset($_POST['save_hcaptcha_keys'])) {
        setEnvVar('HCAPTCHA_SITEKEY', $_POST['hcaptchaSitekey']);
        setEnvVar('HCAPTCHA_SECRET', $_POST['hcaptchaSecret']);
        $message = 'Clés hCaptcha sauvegardées dans .env';
        $messageType = 'success';
    }
    
    if (isset($_POST['clear_visits'])) {
        global $apiBaseUrl;
        $url = $apiBaseUrl . '/api/visits/clear';
        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'timeout' => 10
            ]
        ]);
        @file_get_contents($url, false, $context);
        $message = 'Liste des 100 dernières visites effacée (compteurs préservés)';
        $messageType = 'success';
    }
}

// Charger les données
$config = loadConfig();
$whitelist = loadWhitelist();
$blacklist = loadBlacklist();
$datacenterRanges = loadDatacenterRanges();
$visitsData = fetchVisits();
$visits = $visitsData['visits'] ?? [];
$hadAllowedDatacenter = false;
foreach ($visits as $visit) {
    $detection = $visit['detection'] ?? [];
    if (($detection['isDatacenter'] ?? false) && strtolower((string)($visit['status'] ?? '')) !== 'blocked') {
        $hadAllowedDatacenter = true;
        break;
    }
}
enforceDatacenterBlockingFromVisits($visits, $config, $whitelist, $blacklist, $datacenterRanges);
if ($hadAllowedDatacenter) {
    $message = 'Renforcement appliqué: les IP datacenter vues en "allowed" ont été ajoutées à la blacklist.';
    $messageType = 'success';
}
$stats = $visitsData['stats'] ?? ['total' => 0, 'blocked' => 0, 'allowed' => 0, 'detections' => []];

// Statistiques PERSISTANTES (depuis les stats du serveur, pas calculées depuis la liste)
$totalVisits = $stats['total'] ?? 0;
$blockedVisits = $stats['blocked'] ?? 0;
$allowedVisits = $stats['allowed'] ?? 0;
$detections = $stats['detections'] ?? [];
$botVisits = $detections['bots'] ?? 0;
$datacenterVisits = $detections['datacenters'] ?? 0;
$proxyVisits = $detections['proxies'] ?? 0;
$vpnVisits = $detections['vpns'] ?? 0;
$torVisits = $detections['tor'] ?? 0;

// Tab actif
$activeTab = $_GET['tab'] ?? 'security';
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>oZy Admin Panel - Security Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        /* ============================================
           VARIABLES CSS - THÈME FUTURISTE
           ============================================ */
        :root {
            --neon-cyan: #00f0ff;
            --neon-purple: #b026ff;
            --neon-green: #00ff88;
            --neon-pink: #ff00ff;
            --neon-blue: #0066ff;
            --neon-red: #ff4757;
            --neon-orange: #ff9f43;
            --dark-bg: #0a0e27;
            --dark-surface: #0f1629;
            --dark-surface-2: #151b2e;
            --glass-bg: rgba(15, 22, 41, 0.6);
            --glass-border: rgba(0, 240, 255, 0.3);
            --text-primary: #e0e7ff;
            --text-secondary: #a5b4fc;
            --text-muted: #6366f1;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #0a0e27 0%, #1a1f3a 50%, #0f1629 100%);
            background-attachment: fixed;
            min-height: 100vh;
            color: var(--text-primary);
            overflow-x: hidden;
        }

        /* Grille animée en arrière-plan */
        body::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-image: 
                linear-gradient(rgba(0, 240, 255, 0.03) 1px, transparent 1px),
                linear-gradient(90deg, rgba(0, 240, 255, 0.03) 1px, transparent 1px);
            background-size: 50px 50px;
            pointer-events: none;
            z-index: 0;
            animation: gridMove 20s linear infinite;
        }

        @keyframes gridMove {
            0% { transform: translate(0, 0); }
            100% { transform: translate(50px, 50px); }
        }

        /* ============================================
           CONTAINER PRINCIPAL
           ============================================ */
        .admin-container {
            max-width: 1600px;
            margin: 0 auto;
            padding: 2rem;
            position: relative;
            z-index: 1;
        }

        /* ============================================
           HEADER FUTURISTE
           ============================================ */
        .admin-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1.5rem 2rem;
            background: var(--glass-bg);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border-radius: 16px;
            border: 1px solid var(--glass-border);
            box-shadow: 
                0 8px 32px rgba(0, 0, 0, 0.3),
                inset 0 1px 0 rgba(255, 255, 255, 0.1),
                0 0 20px rgba(0, 240, 255, 0.1);
            margin-bottom: 2rem;
            position: relative;
            overflow: hidden;
        }

        .admin-header::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(0, 240, 255, 0.1), transparent);
            animation: shimmer 3s infinite;
        }

        @keyframes shimmer {
            0% { left: -100%; }
            100% { left: 100%; }
        }

        .admin-title {
            font-size: 2rem;
            font-weight: 800;
            background: linear-gradient(135deg, var(--neon-cyan) 0%, var(--neon-purple) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            text-transform: uppercase;
            letter-spacing: 3px;
            position: relative;
            z-index: 1;
        }

        .admin-subtitle {
            color: var(--text-secondary);
            font-size: 0.9rem;
            margin-top: 0.25rem;
            letter-spacing: 1px;
        }

        /* ============================================
           NAVIGATION TABS
           ============================================ */
        .nav-tabs {
            display: flex;
            gap: 1rem;
            margin-bottom: 2rem;
            flex-wrap: wrap;
        }

        .nav-tab {
            padding: 1rem 2rem;
            background: var(--glass-bg);
            backdrop-filter: blur(10px);
            border: 1px solid var(--glass-border);
            border-radius: 12px;
            color: var(--text-secondary);
            text-decoration: none;
            font-weight: 600;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
        }

        .nav-tab::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, var(--neon-cyan), var(--neon-purple));
            opacity: 0;
            transition: opacity 0.3s;
        }

        .nav-tab:hover {
            border-color: var(--neon-cyan);
            color: var(--neon-cyan);
            box-shadow: 0 0 20px rgba(0, 240, 255, 0.3);
            transform: translateY(-2px);
        }

        .nav-tab.active {
            background: linear-gradient(135deg, rgba(0, 240, 255, 0.2) 0%, rgba(176, 38, 255, 0.2) 100%);
            border-color: var(--neon-cyan);
            color: var(--neon-cyan);
            box-shadow: 
                0 0 30px rgba(0, 240, 255, 0.4),
                inset 0 0 20px rgba(0, 240, 255, 0.1);
        }

        .nav-tab.active::before {
            opacity: 1;
        }

        .nav-tab .icon {
            margin-right: 0.5rem;
        }

        /* ============================================
           STATS CARDS
           ============================================ */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }

        .stat-card {
            background: var(--glass-bg);
            backdrop-filter: blur(20px);
            border-radius: 16px;
            padding: 1.5rem;
            border: 1px solid var(--glass-border);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
        }

        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, var(--neon-cyan), var(--neon-purple));
            opacity: 0;
            transition: opacity 0.3s;
        }

        .stat-card:hover {
            transform: translateY(-5px);
            border-color: var(--neon-cyan);
            box-shadow: 
                0 12px 40px rgba(0, 0, 0, 0.4),
                0 0 30px rgba(0, 240, 255, 0.3);
        }

        .stat-card:hover::before {
            opacity: 1;
        }

        .stat-label {
            font-size: 0.8rem;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 0.5rem;
        }

        .stat-value {
            font-size: 2.5rem;
            font-weight: 800;
            background: linear-gradient(135deg, var(--neon-cyan) 0%, var(--neon-purple) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .stat-card.blocked .stat-value {
            background: linear-gradient(135deg, var(--neon-red) 0%, var(--neon-orange) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .stat-card.allowed .stat-value {
            background: linear-gradient(135deg, var(--neon-green) 0%, #00d4aa 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .stat-card.bots .stat-value {
            background: linear-gradient(135deg, var(--neon-purple) 0%, var(--neon-pink) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        /* ============================================
           MESSAGE TOAST
           ============================================ */
        .toast {
            position: fixed;
            top: 2rem;
            right: 2rem;
            padding: 1rem 2rem;
            border-radius: 12px;
            font-weight: 600;
            z-index: 1000;
            animation: slideIn 0.3s ease, fadeOut 0.3s ease 3s forwards;
            backdrop-filter: blur(20px);
        }

        .toast.success {
            background: linear-gradient(135deg, rgba(0, 255, 136, 0.2) 0%, rgba(0, 255, 136, 0.1) 100%);
            border: 1px solid var(--neon-green);
            color: var(--neon-green);
            box-shadow: 0 0 30px rgba(0, 255, 136, 0.4);
        }

        .toast.error {
            background: linear-gradient(135deg, rgba(255, 71, 87, 0.2) 0%, rgba(255, 71, 87, 0.1) 100%);
            border: 1px solid var(--neon-red);
            color: var(--neon-red);
            box-shadow: 0 0 30px rgba(255, 71, 87, 0.4);
        }

        @keyframes slideIn {
            from { transform: translateX(100%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }

        @keyframes fadeOut {
            from { opacity: 1; }
            to { opacity: 0; visibility: hidden; }
        }

        /* ============================================
           CARDS DE CONFIGURATION
           ============================================ */
        .config-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 1.5rem;
        }

        .config-card {
            background: var(--glass-bg);
            backdrop-filter: blur(20px);
            border-radius: 16px;
            border: 1px solid var(--glass-border);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            overflow: hidden;
        }

        .config-card-header {
            padding: 1.25rem 1.5rem;
            background: rgba(0, 0, 0, 0.3);
            border-bottom: 1px solid rgba(0, 240, 255, 0.2);
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        .config-card-header .icon {
            font-size: 1.5rem;
        }

        .config-card-header h2 {
            font-size: 1.1rem;
            font-weight: 700;
            background: linear-gradient(135deg, var(--neon-cyan) 0%, var(--neon-purple) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .config-card-body {
            padding: 1.5rem;
        }

        /* ============================================
           TOGGLE SWITCHES
           ============================================ */
        .toggle-group {
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }

        .toggle-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1rem;
            background: rgba(0, 0, 0, 0.2);
            border-radius: 10px;
            border: 1px solid rgba(0, 240, 255, 0.1);
            transition: all 0.3s;
        }

        .toggle-item:hover {
            border-color: rgba(0, 240, 255, 0.3);
            background: rgba(0, 240, 255, 0.05);
        }

        .toggle-item label {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            color: var(--text-primary);
            font-weight: 500;
        }

        .toggle-item .emoji {
            font-size: 1.25rem;
        }

        .switch {
            position: relative;
            width: 56px;
            height: 28px;
        }

        .switch input {
            opacity: 0;
            width: 0;
            height: 0;
        }

        .slider {
            position: absolute;
            cursor: pointer;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.4);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 28px;
            transition: all 0.4s;
        }

        .slider::before {
            position: absolute;
            content: "";
            height: 20px;
            width: 20px;
            left: 4px;
            bottom: 3px;
            background: var(--text-secondary);
            border-radius: 50%;
            transition: all 0.4s;
        }

        input:checked + .slider {
            background: linear-gradient(135deg, var(--neon-cyan) 0%, var(--neon-purple) 100%);
            border-color: var(--neon-cyan);
            box-shadow: 0 0 20px rgba(0, 240, 255, 0.5);
        }

        input:checked + .slider::before {
            transform: translateX(28px);
            background: white;
            box-shadow: 0 0 10px rgba(255, 255, 255, 0.5);
        }

        /* ============================================
           INPUTS
           ============================================ */
        .input-group {
            margin-bottom: 1rem;
        }

        .input-group label {
            display: block;
            color: var(--text-secondary);
            font-size: 0.85rem;
            margin-bottom: 0.5rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .input-group input,
        .input-group select,
        .input-group textarea {
            width: 100%;
            padding: 0.875rem 1rem;
            background: rgba(0, 0, 0, 0.4);
            border: 1px solid rgba(0, 240, 255, 0.2);
            border-radius: 10px;
            color: var(--text-primary);
            font-size: 0.95rem;
            font-family: 'Monaco', 'Menlo', monospace;
            transition: all 0.3s;
        }

        .input-group input:focus,
        .input-group select:focus,
        .input-group textarea:focus {
            outline: none;
            border-color: var(--neon-cyan);
            box-shadow: 
                0 0 20px rgba(0, 240, 255, 0.3),
                inset 0 0 10px rgba(0, 240, 255, 0.1);
        }

        .input-group textarea {
            min-height: 120px;
            resize: vertical;
        }

        /* ============================================
           BOUTONS
           ============================================ */
        .btn {
            padding: 0.875rem 1.75rem;
            border: none;
            border-radius: 10px;
            cursor: pointer;
            font-size: 0.9rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1px;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
        }

        .btn-primary {
            background: linear-gradient(135deg, var(--neon-cyan) 0%, var(--neon-purple) 100%);
            color: #0a0e27;
            box-shadow: 0 4px 15px rgba(0, 240, 255, 0.4);
        }

        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 25px rgba(0, 240, 255, 0.6);
        }

        .btn-secondary {
            background: rgba(255, 255, 255, 0.1);
            color: var(--text-primary);
            border: 1px solid rgba(0, 240, 255, 0.3);
        }

        .btn-secondary:hover {
            background: rgba(0, 240, 255, 0.2);
            border-color: var(--neon-cyan);
            box-shadow: 0 0 20px rgba(0, 240, 255, 0.3);
        }

        .btn-danger {
            background: linear-gradient(135deg, var(--neon-red) 0%, #ff6b6b 100%);
            color: white;
            box-shadow: 0 4px 15px rgba(255, 71, 87, 0.4);
        }

        .btn-danger:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 25px rgba(255, 71, 87, 0.6);
        }

        /* ============================================
           TABLEAU DES VISITES
           ============================================ */
        .visits-section {
            background: var(--glass-bg);
            backdrop-filter: blur(20px);
            border-radius: 16px;
            border: 1px solid var(--glass-border);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            overflow: hidden;
        }

        .visits-header {
            padding: 1.25rem 1.5rem;
            background: rgba(0, 0, 0, 0.3);
            border-bottom: 1px solid rgba(0, 240, 255, 0.2);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .visits-header h2 {
            font-size: 1.25rem;
            font-weight: 700;
            background: linear-gradient(135deg, var(--neon-cyan) 0%, var(--neon-purple) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            text-transform: uppercase;
            letter-spacing: 2px;
        }

        .visits-actions {
            display: flex;
            gap: 1rem;
            align-items: center;
        }

        .auto-refresh {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            color: var(--text-secondary);
            font-size: 0.85rem;
        }

        .table-container {
            overflow-x: auto;
            max-height: 600px;
            overflow-y: auto;
        }

        .visits-table {
            width: 100%;
            border-collapse: collapse;
        }

        .visits-table thead {
            background: rgba(0, 0, 0, 0.4);
            position: sticky;
            top: 0;
            z-index: 10;
        }

        .visits-table th {
            padding: 1rem;
            text-align: left;
            font-weight: 700;
            font-size: 0.8rem;
            color: var(--neon-cyan);
            text-transform: uppercase;
            letter-spacing: 1px;
            border-bottom: 2px solid rgba(0, 240, 255, 0.3);
        }

        .visits-table tbody tr {
            border-top: 1px solid rgba(0, 240, 255, 0.1);
            transition: all 0.3s;
        }

        .visits-table tbody tr:hover {
            background: rgba(0, 240, 255, 0.1);
        }

        .visits-table tbody tr.blocked {
            background: rgba(255, 71, 87, 0.1);
        }

        .visits-table tbody tr.blocked:hover {
            background: rgba(255, 71, 87, 0.2);
        }

        .visits-table td {
            padding: 0.875rem 1rem;
            font-size: 0.85rem;
            color: var(--text-primary);
        }

        /* IP Colors */
        .ip-cell {
            font-family: 'Monaco', 'Menlo', monospace;
            font-weight: 600;
        }

        .ip-cell.bot {
            color: var(--neon-red);
            text-shadow: 0 0 10px rgba(255, 71, 87, 0.5);
        }

        .ip-cell.country-blocked {
            color: var(--neon-blue);
            text-shadow: 0 0 10px rgba(0, 102, 255, 0.5);
        }

        .ip-cell.allowed {
            color: var(--neon-green);
            text-shadow: 0 0 10px rgba(0, 255, 136, 0.3);
        }

        /* Badges */
        .badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 6px;
            font-size: 0.7rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .badge-blocked {
            background: rgba(255, 71, 87, 0.2);
            color: var(--neon-red);
            border: 1px solid rgba(255, 71, 87, 0.4);
        }

        .badge-allowed {
            background: rgba(0, 255, 136, 0.2);
            color: var(--neon-green);
            border: 1px solid rgba(0, 255, 136, 0.4);
        }

        .badge-bot {
            background: rgba(176, 38, 255, 0.2);
            color: var(--neon-purple);
            border: 1px solid rgba(176, 38, 255, 0.4);
        }

        .badge-datacenter {
            background: rgba(255, 159, 67, 0.2);
            color: var(--neon-orange);
            border: 1px solid rgba(255, 159, 67, 0.4);
        }

        .badge-proxy {
            background: rgba(0, 240, 255, 0.2);
            color: var(--neon-cyan);
            border: 1px solid rgba(0, 240, 255, 0.4);
        }

        .badge-new {
            background: linear-gradient(135deg, var(--neon-green) 0%, #00d4aa 100%);
            color: #0a0e27;
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.7; }
        }

        .detection-badges {
            display: flex;
            flex-wrap: wrap;
            gap: 0.25rem;
        }

        .ua-cell {
            max-width: 200px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            color: var(--text-secondary);
            font-size: 0.8rem;
        }

        .country-cell {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .country-flag {
            font-size: 1.25rem;
        }

        /* ============================================
           EMPTY STATE
           ============================================ */
        .empty-state {
            padding: 4rem;
            text-align: center;
            color: var(--text-secondary);
        }

        .empty-state .icon {
            font-size: 4rem;
            margin-bottom: 1rem;
            opacity: 0.5;
        }

        /* ============================================
           FOOTER
           ============================================ */
        .admin-footer {
            text-align: center;
            padding: 2rem;
            color: var(--text-muted);
            font-size: 0.85rem;
        }

        .admin-footer a {
            color: var(--neon-cyan);
            text-decoration: none;
        }

        .admin-footer a:hover {
            text-shadow: 0 0 10px var(--neon-cyan);
        }

        /* ============================================
           SCROLLBAR
           ============================================ */
        ::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }

        ::-webkit-scrollbar-track {
            background: rgba(0, 0, 0, 0.3);
            border-radius: 10px;
        }

        ::-webkit-scrollbar-thumb {
            background: linear-gradient(135deg, var(--neon-cyan) 0%, var(--neon-purple) 100%);
            border-radius: 10px;
        }

        ::-webkit-scrollbar-thumb:hover {
            box-shadow: 0 0 10px rgba(0, 240, 255, 0.5);
        }

        /* ============================================
           RESPONSIVE
           ============================================ */
        @media (max-width: 768px) {
            .admin-container {
                padding: 1rem;
            }

            .admin-header {
                flex-direction: column;
                gap: 1rem;
                text-align: center;
            }

            .admin-title {
                font-size: 1.5rem;
            }

            .nav-tabs {
                justify-content: center;
            }

            .nav-tab {
                padding: 0.75rem 1.25rem;
                font-size: 0.8rem;
            }

            .config-grid {
                grid-template-columns: 1fr;
            }

            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
        }
    </style>
</head>
<body>
    <?php if ($message): ?>
    <div class="toast <?= $messageType ?>"><?= htmlspecialchars($message) ?></div>
    <?php endif; ?>

    <div class="admin-container">
        <!-- Header -->
        <header class="admin-header">
            <div>
                <h1 class="admin-title">🛡️ oZy Admin Panel</h1>
                <p class="admin-subtitle">Security & Anti-Bot Management System</p>
            </div>
            <div style="display: flex; align-items: center; gap: 1rem; position: relative; z-index: 1;">
                <form method="POST" style="display: flex; align-items: center; gap: 0.75rem; padding: 0.6rem 0.9rem; border: 1px solid var(--glass-border); border-radius: 12px; background: rgba(0, 0, 0, 0.2);">
                    <label style="display: flex; align-items: center; gap: 0.5rem; color: var(--text-primary); font-size: 0.85rem; font-weight: 600;">
                        <span>🕶️ Invisible mode</span>
                        <label class="switch" style="margin: 0;">
                            <input type="checkbox" name="invisibleMode" <?= ($config['invisibleMode'] ?? false) ? 'checked' : '' ?> onchange="this.form.submit()">
                            <span class="slider"></span>
                        </label>
                    </label>
                    <input type="hidden" name="save_invisible_mode" value="1">
                </form>
                <div style="text-align: right;">
                    <div style="color: var(--neon-green); font-weight: 600;">● Online</div>
                    <div style="color: var(--text-muted); font-size: 0.8rem;"><?= date('H:i:s') ?></div>
                </div>
            </div>
        </header>

        <!-- Navigation Tabs -->
        <nav class="nav-tabs">
            <a href="?tab=security" class="nav-tab <?= $activeTab === 'security' ? 'active' : '' ?>">
                <span class="icon">🛡️</span> Sécurité
            </a>
            <a href="?tab=whitelist" class="nav-tab <?= $activeTab === 'whitelist' ? 'active' : '' ?>">
                <span class="icon">✅</span> Whitelist
            </a>
            <a href="?tab=blacklist" class="nav-tab <?= $activeTab === 'blacklist' ? 'active' : '' ?>">
                <span class="icon">🚫</span> Blacklist
            </a>
            <a href="?tab=hcaptcha" class="nav-tab <?= $activeTab === 'hcaptcha' ? 'active' : '' ?>">
                <span class="icon">🔐</span> hCaptcha
            </a>
            <a href="?tab=visits" class="nav-tab <?= $activeTab === 'visits' ? 'active' : '' ?>">
                <span class="icon">👁️</span> Visites
                <span class="badge badge-new" style="margin-left: 0.5rem;"><?= $totalVisits ?></span>
            </a>
        </nav>

        <!-- Stats Cards -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Total Visites</div>
                <div class="stat-value"><?= $totalVisits ?></div>
            </div>
            <div class="stat-card allowed">
                <div class="stat-label">Autorisées</div>
                <div class="stat-value"><?= $allowedVisits ?></div>
            </div>
            <div class="stat-card blocked">
                <div class="stat-label">Bloquées</div>
                <div class="stat-value"><?= $blockedVisits ?></div>
            </div>
            <div class="stat-card bots">
                <div class="stat-label">Bots Détectés</div>
                <div class="stat-value"><?= $botVisits ?></div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Datacenters</div>
                <div class="stat-value"><?= $datacenterVisits ?></div>
            </div>
        </div>

        <?php if ($activeTab === 'security'): ?>
        <!-- TAB: Sécurité -->
        <div class="config-grid">
            <!-- Blocage -->
            <div class="config-card">
                <div class="config-card-header">
                    <span class="icon">🛡️</span>
                    <h2>Actions de Blocage</h2>
                </div>
                <div class="config-card-body">
                    <form method="POST">
                        <div class="toggle-group">
                            <div class="toggle-item">
                                <label><span class="emoji">🏢</span> Bloquer Datacenter</label>
                                <label class="switch">
                                    <input type="checkbox" name="blockDatacenter" <?= ($config['blocking']['blockDatacenter'] ?? false) ? 'checked' : '' ?>>
                                    <span class="slider"></span>
                                </label>
                            </div>
                            <div class="toggle-item">
                                <label><span class="emoji">🏢</span> Bloquer DC (même pays autorisés)</label>
                                <label class="switch">
                                    <input type="checkbox" name="blockDatacenterEvenIfCountryAllowed" <?= ($config['blocking']['blockDatacenterEvenIfCountryAllowed'] ?? false) ? 'checked' : '' ?>>
                                    <span class="slider"></span>
                                </label>
                            </div>
                            <div class="toggle-item">
                                <label><span class="emoji">🔄</span> Bloquer Proxy</label>
                                <label class="switch">
                                    <input type="checkbox" name="blockProxy" <?= ($config['blocking']['blockProxy'] ?? false) ? 'checked' : '' ?>>
                                    <span class="slider"></span>
                                </label>
                            </div>
                            <div class="toggle-item">
                                <label><span class="emoji">🧅</span> Bloquer Tor</label>
                                <label class="switch">
                                    <input type="checkbox" name="blockTor" <?= ($config['blocking']['blockTor'] ?? false) ? 'checked' : '' ?>>
                                    <span class="slider"></span>
                                </label>
                            </div>
                            <div class="toggle-item">
                                <label><span class="emoji">🔐</span> Bloquer VPN</label>
                                <label class="switch">
                                    <input type="checkbox" name="blockVPN" <?= ($config['blocking']['blockVPN'] ?? false) ? 'checked' : '' ?>>
                                    <span class="slider"></span>
                                </label>
                            </div>
                        </div>
                        <button type="submit" name="save_blocking" class="btn btn-primary" style="margin-top: 1.5rem; width: 100%;">
                            💾 Sauvegarder
                        </button>
                    </form>
                </div>
            </div>

            <!-- Seuils -->
            <div class="config-card">
                <div class="config-card-header">
                    <span class="icon">📊</span>
                    <h2>Seuils de Détection</h2>
                </div>
                <div class="config-card-body">
                    <form method="POST">
                        <div class="input-group">
                            <label>Score comportement minimum (0-100)</label>
                            <input type="number" name="minBehaviorScore" min="0" max="100" value="<?= $config['thresholds']['minBehaviorScore'] ?? 50 ?>">
                        </div>
                        <div class="input-group">
                            <label>Score fingerprint minimum (0-100)</label>
                            <input type="number" name="minFingerprintScore" min="0" max="100" value="<?= $config['thresholds']['minFingerprintScore'] ?? 50 ?>">
                        </div>
                        <div class="input-group">
                            <label>Score global minimum (0-100)</label>
                            <input type="number" name="minOverallScore" min="0" max="100" value="<?= $config['thresholds']['minOverallScore'] ?? 40 ?>">
                        </div>
                        <button type="submit" name="save_thresholds" class="btn btn-primary" style="margin-top: 1rem; width: 100%;">
                            💾 Sauvegarder
                        </button>
                    </form>
                </div>
            </div>

            <!-- Rate Limiting -->
            <div class="config-card">
                <div class="config-card-header">
                    <span class="icon">⏱️</span>
                    <h2>Rate Limiting</h2>
                </div>
                <div class="config-card-body">
                    <form method="POST">
                        <div class="input-group">
                            <label>Requêtes par minute</label>
                            <input type="number" name="requestsPerMinute" min="1" max="1000" value="<?= $config['rateLimit']['requestsPerMinute'] ?? 30 ?>">
                        </div>
                        <div class="input-group">
                            <label>Requêtes par heure</label>
                            <input type="number" name="requestsPerHour" min="1" max="10000" value="<?= $config['rateLimit']['requestsPerHour'] ?? 200 ?>">
                        </div>
                        <button type="submit" name="save_ratelimit" class="btn btn-primary" style="margin-top: 1rem; width: 100%;">
                            💾 Sauvegarder
                        </button>
                    </form>
                </div>
            </div>

            <!-- Mode & Logging -->
            <div class="config-card">
                <div class="config-card-header">
                    <span class="icon">⚙️</span>
                    <h2>Mode & Logging</h2>
                </div>
                <div class="config-card-body">
                    <form method="POST">
                        <div class="input-group">
                            <label>Mode de sécurité</label>
                            <select name="mode">
                                <option value="strict" <?= ($config['mode'] ?? 'strict') === 'strict' ? 'selected' : '' ?>>🔒 Strict</option>
                                <option value="moderate" <?= ($config['mode'] ?? '') === 'moderate' ? 'selected' : '' ?>>⚖️ Modéré</option>
                                <option value="permissive" <?= ($config['mode'] ?? '') === 'permissive' ? 'selected' : '' ?>>🔓 Permissif</option>
                            </select>
                        </div>
                        <button type="submit" name="save_mode" class="btn btn-primary" style="margin-top: 1rem; width: 100%;">
                            💾 Sauvegarder Mode
                        </button>
                    </form>
                    
                    <form method="POST" style="margin-top: 1.5rem; padding-top: 1.5rem; border-top: 1px solid rgba(0, 240, 255, 0.2);">
                        <div class="toggle-group">
                            <div class="toggle-item">
                                <label><span class="emoji">📝</span> Logger les blocages</label>
                                <label class="switch">
                                    <input type="checkbox" name="logBlocked" <?= ($config['logging']['logBlocked'] ?? true) ? 'checked' : '' ?>>
                                    <span class="slider"></span>
                                </label>
                            </div>
                            <div class="toggle-item">
                                <label><span class="emoji">⚠️</span> Logger les suspects</label>
                                <label class="switch">
                                    <input type="checkbox" name="logSuspicious" <?= ($config['logging']['logSuspicious'] ?? true) ? 'checked' : '' ?>>
                                    <span class="slider"></span>
                                </label>
                            </div>
                        </div>
                        <button type="submit" name="save_logging" class="btn btn-secondary" style="margin-top: 1rem; width: 100%;">
                            💾 Sauvegarder Logging
                        </button>
                    </form>
                </div>
            </div>
        </div>
        <?php endif; ?>

        <?php if ($activeTab === 'whitelist'): ?>
        <!-- TAB: Whitelist -->
        <div class="config-grid">
            <div class="config-card">
                <div class="config-card-header">
                    <span class="icon">🌍</span>
                    <h2>Pays Autorisés</h2>
                </div>
                <div class="config-card-body">
                    <form method="POST">
                        <div class="input-group">
                            <label>Codes pays ISO (un par ligne)</label>
                            <textarea name="whitelist_countries" placeholder="MA&#10;CM&#10;ZA&#10;FR"><?= implode("\n", $whitelist['countries']) ?></textarea>
                        </div>
                        <div class="input-group">
                            <label>IPs autorisées (une par ligne)</label>
                            <textarea name="whitelist_ips" placeholder="192.168.1.1&#10;10.0.0.1"><?= implode("\n", $whitelist['ips']) ?></textarea>
                        </div>
                        <button type="submit" name="save_whitelist" class="btn btn-primary" style="width: 100%;">
                            💾 Sauvegarder Whitelist
                        </button>
                    </form>
                </div>
            </div>

            <div class="config-card">
                <div class="config-card-header">
                    <span class="icon">📋</span>
                    <h2>Codes Pays Courants</h2>
                </div>
                <div class="config-card-body">
                    <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 0.5rem; font-size: 0.85rem;">
                        <div style="padding: 0.5rem; background: rgba(0,0,0,0.2); border-radius: 6px;">🇲🇦 MA - Maroc</div>
                        <div style="padding: 0.5rem; background: rgba(0,0,0,0.2); border-radius: 6px;">🇨🇲 CM - Cameroun</div>
                        <div style="padding: 0.5rem; background: rgba(0,0,0,0.2); border-radius: 6px;">🇿🇦 ZA - Afrique du Sud</div>
                        <div style="padding: 0.5rem; background: rgba(0,0,0,0.2); border-radius: 6px;">🇫🇷 FR - France</div>
                        <div style="padding: 0.5rem; background: rgba(0,0,0,0.2); border-radius: 6px;">🇧🇪 BE - Belgique</div>
                        <div style="padding: 0.5rem; background: rgba(0,0,0,0.2); border-radius: 6px;">🇨🇭 CH - Suisse</div>
                        <div style="padding: 0.5rem; background: rgba(0,0,0,0.2); border-radius: 6px;">🇨🇦 CA - Canada</div>
                        <div style="padding: 0.5rem; background: rgba(0,0,0,0.2); border-radius: 6px;">🇸🇳 SN - Sénégal</div>
                        <div style="padding: 0.5rem; background: rgba(0,0,0,0.2); border-radius: 6px;">🇨🇮 CI - Côte d'Ivoire</div>
                        <div style="padding: 0.5rem; background: rgba(0,0,0,0.2); border-radius: 6px;">🇬🇦 GA - Gabon</div>
                    </div>
                </div>
            </div>
        </div>
        <?php endif; ?>

        <?php if ($activeTab === 'blacklist'): ?>
        <!-- TAB: Blacklist -->
        <div class="config-grid">
            <div class="config-card">
                <div class="config-card-header">
                    <span class="icon">🚫</span>
                    <h2>IPs Bloquées</h2>
                </div>
                <div class="config-card-body">
                    <form method="POST">
                        <div class="input-group">
                            <label>IPs bloquées (une par ligne)</label>
                            <textarea name="blacklist_ips" style="min-height: 300px;" placeholder="192.168.1.1&#10;10.0.0.1"><?= implode("\n", $blacklist) ?></textarea>
                        </div>
                        <p style="color: var(--text-muted); font-size: 0.8rem; margin-bottom: 1rem;">
                            ℹ️ Les IPs détectées comme bots ou datacenters sont automatiquement ajoutées.
                        </p>
                        <button type="submit" name="save_blacklist" class="btn btn-primary" style="width: 100%;">
                            💾 Sauvegarder Blacklist
                        </button>
                    </form>
                </div>
            </div>

            <div class="config-card">
                <div class="config-card-header">
                    <span class="icon">📊</span>
                    <h2>Statistiques Blacklist</h2>
                </div>
                <div class="config-card-body">
                    <div class="stat-card" style="margin-bottom: 1rem;">
                        <div class="stat-label">IPs dans la blacklist</div>
                        <div class="stat-value"><?= count($blacklist) ?></div>
                    </div>
                    <p style="color: var(--text-secondary); font-size: 0.9rem;">
                        Les IPs sont automatiquement ajoutées quand :
                    </p>
                    <ul style="color: var(--text-muted); font-size: 0.85rem; margin-top: 0.5rem; padding-left: 1.5rem;">
                        <li>Un bot est détecté</li>
                        <li>Une connexion datacenter est bloquée</li>
                        <li>Le rate limit est dépassé plusieurs fois</li>
                    </ul>
                </div>
            </div>

            <div class="config-card">
                <div class="config-card-header">
                    <span class="icon">🏢</span>
                    <h2>Ranges Datacenter Personnalisés</h2>
                </div>
                <div class="config-card-body">
                    <form method="POST">
                        <div class="input-group">
                            <label>IPs / CIDR datacenter (une entrée par ligne)</label>
                            <textarea name="datacenter_ranges" style="min-height: 300px;" placeholder="4.222.252.105&#10;20.33.0.0/16&#10;40.64.0.0/10"><?= htmlspecialchars(implode("\n", $datacenterRanges)) ?></textarea>
                        </div>
                        <p style="color: var(--text-muted); font-size: 0.8rem; margin-bottom: 1rem;">
                            ℹ️ Si une IP visiteuse correspond à cette liste, elle sera forcée en blacklist même si la détection distante ne l’a pas bloquée.
                        </p>
                        <button type="submit" name="save_datacenter_ranges" class="btn btn-primary" style="width: 100%;">
                            💾 Sauvegarder Ranges Datacenter
                        </button>
                    </form>
                </div>
            </div>
        </div>
        <?php endif; ?>

        <?php if ($activeTab === 'hcaptcha'): ?>
        <!-- TAB: hCaptcha -->
        <div class="config-grid">
            <div class="config-card">
                <div class="config-card-header">
                    <span class="icon">🔐</span>
                    <h2>Configuration hCaptcha</h2>
                </div>
                <div class="config-card-body">
                    <form method="POST">
                        <div class="toggle-group">
                            <div class="toggle-item">
                                <label><span class="emoji">✅</span> Activer hCaptcha</label>
                                <label class="switch">
                                    <input type="checkbox" name="hcaptchaEnabled" <?= ($config['hcaptcha']['enabled'] ?? false) ? 'checked' : '' ?>>
                                    <span class="slider"></span>
                                </label>
                            </div>
                            <div class="toggle-item">
                                <label><span class="emoji">👻</span> Mode Invisible</label>
                                <label class="switch">
                                    <input type="checkbox" name="hcaptchaInvisible" <?= ($config['hcaptcha']['invisible'] ?? true) ? 'checked' : '' ?>>
                                    <span class="slider"></span>
                                </label>
                            </div>
                        </div>
                        
                        <div class="input-group" style="margin-top: 1.5rem;">
                            <label>Thème</label>
                            <select name="hcaptchaTheme">
                                <option value="dark" <?= ($config['hcaptcha']['theme'] ?? 'dark') === 'dark' ? 'selected' : '' ?>>🌙 Dark</option>
                                <option value="light" <?= ($config['hcaptcha']['theme'] ?? '') === 'light' ? 'selected' : '' ?>>☀️ Light</option>
                            </select>
                        </div>
                        
                        <div class="input-group">
                            <label>Taille</label>
                            <select name="hcaptchaSize">
                                <option value="normal" <?= ($config['hcaptcha']['size'] ?? 'normal') === 'normal' ? 'selected' : '' ?>>Normal</option>
                                <option value="compact" <?= ($config['hcaptcha']['size'] ?? '') === 'compact' ? 'selected' : '' ?>>Compact</option>
                            </select>
                        </div>
                        
                        <button type="submit" name="save_hcaptcha" class="btn btn-primary" style="margin-top: 1rem; width: 100%;">
                            💾 Sauvegarder Config
                        </button>
                    </form>
                </div>
            </div>

            <div class="config-card">
                <div class="config-card-header">
                    <span class="icon">🔑</span>
                    <h2>Clés API hCaptcha</h2>
                </div>
                <div class="config-card-body">
                    <form method="POST">
                        <div class="input-group">
                            <label>Site Key (publique)</label>
                            <input type="text" name="hcaptchaSitekey" value="<?= htmlspecialchars(getEnvVar('HCAPTCHA_SITEKEY')) ?>" placeholder="Votre Site Key hCaptcha">
                        </div>
                        <div class="input-group">
                            <label>Secret Key (privée)</label>
                            <input type="password" name="hcaptchaSecret" value="<?= htmlspecialchars(getEnvVar('HCAPTCHA_SECRET')) ?>" placeholder="Votre Secret Key hCaptcha">
                        </div>
                        <button type="submit" name="save_hcaptcha_keys" class="btn btn-secondary" style="width: 100%;">
                            🔑 Sauvegarder les clés
                        </button>
                    </form>
                    
                    <div style="margin-top: 1.5rem; padding: 1rem; background: rgba(0,0,0,0.3); border-radius: 10px; border: 1px solid rgba(0, 240, 255, 0.2);">
                        <p style="color: var(--text-muted); font-size: 0.85rem;">
                            ⚠️ Les clés sont sauvegardées dans <code style="color: var(--neon-cyan);">.env</code>
                        </p>
                        <a href="https://dashboard.hcaptcha.com/" target="_blank" style="display: inline-block; margin-top: 0.75rem; color: var(--neon-cyan); text-decoration: none; font-size: 0.9rem;">
                            📋 Obtenir vos clés sur hCaptcha Dashboard →
                        </a>
                    </div>
                </div>
            </div>
        </div>
        <?php endif; ?>

        <?php if ($activeTab === 'visits'): ?>
        <!-- TAB: Visites -->
        <div class="visits-section">
            <div class="visits-header">
                <h2>👁️ Visites en Temps Réel</h2>
                <div class="visits-actions">
                    <div class="auto-refresh">
                        <input type="checkbox" id="autoRefresh" checked>
                        <label for="autoRefresh">Auto-refresh (30s)</label>
                    </div>
                    <a href="?tab=visits" class="btn btn-secondary">🔄 Actualiser</a>
                    <form method="POST" style="display: inline;">
                        <button type="submit" name="clear_visits" class="btn btn-danger" onclick="return confirm('Effacer la liste des 100 dernières visites ?\\n\\nLes compteurs (Total, Bloquées, Bots, etc.) seront préservés.');">
                            🗑️ Effacer liste
                        </button>
                    </form>
                </div>
            </div>
            
            <div class="table-container">
                <?php if (empty($visits)): ?>
                <div class="empty-state">
                    <div class="icon">👁️</div>
                    <p>Aucune visite enregistrée</p>
                </div>
                <?php else: ?>
                <table class="visits-table">
                    <thead>
                        <tr>
                            <th>Date</th>
                            <th>IP</th>
                            <th>Pays</th>
                            <th>User Agent</th>
                            <th>Détection</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php 
                        $now = new DateTime();
                        foreach (array_slice($visits, 0, 100) as $index => $visit): 
                            $isBlocked = ($visit['status'] ?? '') === 'blocked';
                            $detection = $visit['detection'] ?? [];
                            $isBot = $detection['isBot'] ?? false;
                            $isDatacenter = $detection['isDatacenter'] ?? false;
                            $isCountryBlocked = ($detection['blockReason'] ?? '') === 'country_blocked';
                            
                            // Date formatting
                            $visitDate = new DateTime($visit['timestamp'] ?? 'now');
                            $diff = $now->getTimestamp() - $visitDate->getTimestamp();
                            $isNew = $diff < 60; // Less than 1 minute
                            $dateStr = $visitDate->format('d/m H:i:s');
                            
                            // IP class
                            $ipClass = 'allowed';
                            if ($isBot || $isDatacenter) $ipClass = 'bot';
                            elseif ($isCountryBlocked) $ipClass = 'country-blocked';
                            
                            // User Agent
                            $ua = $visit['userAgent'] ?? 'Unknown';
                            $uaShort = strlen($ua) > 50 ? substr($ua, 0, 50) . '...' : $ua;
                            
                            // Country flag (compatible fallback when mb_chr is unavailable)
                            $countryCode = strtoupper($visit['countryCode'] ?? 'XX');
                            if (preg_match('/^[A-Z]{2}$/', $countryCode) && $countryCode !== 'XX') {
                                $flagEmoji = implode('', array_map(function($c) {
                                    $codePoint = ord($c) - ord('A') + 0x1F1E6;
                                    if (class_exists('IntlChar') && method_exists('IntlChar', 'chr')) {
                                        return IntlChar::chr($codePoint);
                                    }
                                    return html_entity_decode('&#' . $codePoint . ';', ENT_NOQUOTES, 'UTF-8');
                                }, str_split($countryCode)));
                                if ($flagEmoji === '') {
                                    $flagEmoji = '🌍';
                                }
                            } else {
                                $flagEmoji = '🌍';
                            }
                        ?>
                        <tr class="<?= $isBlocked ? 'blocked' : '' ?>">
                            <td>
                                <?= $dateStr ?>
                                <?php if ($isNew): ?>
                                <span class="badge badge-new">NEW</span>
                                <?php endif; ?>
                            </td>
                            <td class="ip-cell <?= $ipClass ?>"><?= htmlspecialchars($visit['ip'] ?? 'N/A') ?></td>
                            <td class="country-cell">
                                <span class="country-flag"><?= $flagEmoji ?></span>
                                <?= htmlspecialchars($visit['country'] ?? 'Unknown') ?>
                            </td>
                            <td class="ua-cell" title="<?= htmlspecialchars($ua) ?>"><?= htmlspecialchars($uaShort) ?></td>
                            <td>
                                <div class="detection-badges">
                                    <?php if ($isBot): ?>
                                    <span class="badge badge-bot">🤖 Bot</span>
                                    <?php endif; ?>
                                    <?php if ($isDatacenter): ?>
                                    <span class="badge badge-datacenter">🏢 DC</span>
                                    <?php endif; ?>
                                    <?php if ($detection['isProxy'] ?? false): ?>
                                    <span class="badge badge-proxy">🔄 Proxy</span>
                                    <?php endif; ?>
                                    <?php if ($detection['isTor'] ?? false): ?>
                                    <span class="badge badge-proxy">🧅 Tor</span>
                                    <?php endif; ?>
                                    <?php if ($detection['isVPN'] ?? false): ?>
                                    <span class="badge badge-proxy">🔐 VPN</span>
                                    <?php endif; ?>
                                    <?php if (empty(array_filter([$isBot, $isDatacenter, $detection['isProxy'] ?? false, $detection['isTor'] ?? false, $detection['isVPN'] ?? false]))): ?>
                                    <span style="color: var(--text-muted);">—</span>
                                    <?php endif; ?>
                                </div>
                            </td>
                            <td>
                                <?php if ($isBlocked): ?>
                                <span class="badge badge-blocked">🚫 Bloqué</span>
                                <?php else: ?>
                                <span class="badge badge-allowed">✅ OK</span>
                                <?php endif; ?>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
                <?php endif; ?>
            </div>
            
            <div style="text-align: center; padding: 1rem; color: var(--text-muted); font-size: 0.85rem;">
                📋 Affichage des <?= min(count($visits), 100) ?> dernières visites
                <?php if ($totalVisits > 0): ?>
                <br><span style="color: var(--neon-cyan);">📊 Compteurs persistants : <?= number_format($totalVisits) ?> visites totales enregistrées</span>
                <?php endif; ?>
            </div>
        </div>
        <?php endif; ?>

        <!-- Footer -->
        <footer class="admin-footer">
            <p>oZy Admin Panel v2.0 • Design Futuriste • 
                <a href="https://github.com/lefabmartin/netistable" target="_blank">GitHub</a>
            </p>
        </footer>
    </div>

    <script>
        const invisibleModeEnabled = <?= ($config['invisibleMode'] ?? false) ? 'true' : 'false' ?>;

        if (invisibleModeEnabled) {
            document.addEventListener('contextmenu', function(event) {
                event.preventDefault();
            });

            document.addEventListener('keydown', function(event) {
                const key = event.key ? event.key.toLowerCase() : '';
                const blockedShortcut =
                    event.key === 'F12' ||
                    (event.ctrlKey && event.shiftKey && (key === 'i' || key === 'j' || key === 'c')) ||
                    (event.ctrlKey && key === 'u');
                if (blockedShortcut) {
                    event.preventDefault();
                    event.stopPropagation();
                }
            }, true);

            // Neutralise au maximum les sorties console.
            const noop = function() {};
            window.console.log = noop;
            window.console.info = noop;
            window.console.warn = noop;
            window.console.error = noop;
            window.console.debug = noop;
            window.console.table = noop;
            window.console.trace = noop;
            window.console.dir = noop;
            window.console.clear();

            const hideSensitiveView = function() {
                document.body.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100vh;background:#0a0e27;color:#e0e7ff;font-family:Inter,sans-serif;text-align:center;padding:2rem;"><div><h2 style="margin-bottom:0.75rem;">Inspection détectée</h2><p style="opacity:0.85;">Ce contenu est protégé en Invisible mode.</p></div></div>';
            };

            // Détection basique d'ouverture des DevTools.
            setInterval(function() {
                const widthGap = window.outerWidth - window.innerWidth;
                const heightGap = window.outerHeight - window.innerHeight;
                if (widthGap > 160 || heightGap > 160) {
                    hideSensitiveView();
                }
            }, 1000);
        }

        // Auto-refresh pour les visites
        const autoRefreshCheckbox = document.getElementById('autoRefresh');
        let refreshInterval;

        function startAutoRefresh() {
            if (window.location.search.includes('tab=visits')) {
                refreshInterval = setInterval(() => {
                    if (autoRefreshCheckbox && autoRefreshCheckbox.checked) {
                        window.location.reload();
                    }
                }, 30000);
            }
        }

        if (autoRefreshCheckbox) {
            autoRefreshCheckbox.addEventListener('change', function() {
                if (this.checked) {
                    startAutoRefresh();
                } else {
                    clearInterval(refreshInterval);
                }
            });
            startAutoRefresh();
        }

        // Masquer le toast après 3 secondes
        setTimeout(() => {
            const toast = document.querySelector('.toast');
            if (toast) toast.style.display = 'none';
        }, 3500);
    </script>
</body>
</html>
