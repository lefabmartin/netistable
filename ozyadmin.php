<?php
/**
 * OZY ADMIN - Panel de Gestion Anti-Bot
 * Gestion centralisée de la sécurité
 */

// Configuration
$configFile = __DIR__ . '/security-config.json';
$whitelistFile = __DIR__ . '/whitelist.txt';
$blacklistFile = __DIR__ . '/blacklist.txt';
$botfuckFile = __DIR__ . '/botfuck.txt';
$hcaptchaEnvFile = __DIR__ . '/server/.env';

// Authentification simple (à personnaliser)
$adminPassword = 'ozy2024'; // Changez ce mot de passe !

session_start();

// Gestion de la connexion
if (isset($_POST['login'])) {
    if ($_POST['password'] === $adminPassword) {
        $_SESSION['authenticated'] = true;
    } else {
        $loginError = 'Mot de passe incorrect';
    }
}

if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: ozyadmin.php');
    exit;
}

// Charger la configuration
function loadConfig($file) {
    if (file_exists($file)) {
        return json_decode(file_get_contents($file), true);
    }
    return [];
}

// Sauvegarder la configuration
function saveConfig($file, $config) {
    file_put_contents($file, json_encode($config, JSON_PRETTY_PRINT));
}

// Charger un fichier texte (whitelist, blacklist, etc.)
function loadTextFile($file) {
    if (file_exists($file)) {
        return array_filter(array_map('trim', file($file)), function($line) {
            return $line && !str_starts_with($line, '#');
        });
    }
    return [];
}

// Charger les variables d'environnement depuis .env
function loadEnvFile($file) {
    $env = [];
    if (file_exists($file)) {
        $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line && !str_starts_with($line, '#')) {
                $parts = explode('=', $line, 2);
                if (count($parts) === 2) {
                    $key = trim($parts[0]);
                    $value = trim($parts[1], '"\'');
                    $env[$key] = $value;
                }
            }
        }
    }
    return $env;
}

// Sauvegarder les variables d'environnement dans .env
function saveEnvFile($file, $env) {
    $content = "# Configuration du serveur\n";
    $content .= "# Généré par OZY Admin\n\n";
    
    foreach ($env as $key => $value) {
        $content .= "$key=$value\n";
    }
    
    file_put_contents($file, $content);
}

// Sauvegarder un fichier texte
function saveTextFile($file, $lines, $header = '') {
    $content = $header ? "# $header\n" : '';
    $content .= implode("\n", array_filter($lines));
    file_put_contents($file, $content);
}

// Traitement des actions
if (isset($_SESSION['authenticated']) && $_SESSION['authenticated']) {
    $config = loadConfig($configFile);
    
    // Mise à jour de la configuration
    if (isset($_POST['save_config'])) {
        $config['blocking']['blockDatacenter'] = isset($_POST['blockDatacenter']);
        $config['blocking']['blockDatacenterEvenIfCountryAllowed'] = isset($_POST['blockDatacenterEvenIfCountryAllowed']);
        $config['blocking']['blockProxy'] = isset($_POST['blockProxy']);
        $config['blocking']['blockTor'] = isset($_POST['blockTor']);
        $config['blocking']['blockVPN'] = isset($_POST['blockVPN']);
        
        $config['thresholds']['minBehaviorScore'] = (int)$_POST['minBehaviorScore'];
        $config['thresholds']['minFingerprintScore'] = (int)$_POST['minFingerprintScore'];
        $config['thresholds']['minOverallScore'] = (int)$_POST['minOverallScore'];
        
        $config['rateLimit']['requestsPerMinute'] = (int)$_POST['requestsPerMinute'];
        $config['rateLimit']['requestsPerHour'] = (int)$_POST['requestsPerHour'];
        
        $config['mode'] = $_POST['mode'];
        
        $config['logging']['logBlocked'] = isset($_POST['logBlocked']);
        $config['logging']['logSuspicious'] = isset($_POST['logSuspicious']);
        $config['logging']['sendTelegramAlerts'] = isset($_POST['sendTelegramAlerts']);
        
        // hCaptcha
        $config['hcaptcha']['enabled'] = isset($_POST['hcaptchaEnabled']);
        $config['hcaptcha']['invisible'] = isset($_POST['hcaptchaInvisible']);
        $config['hcaptcha']['theme'] = $_POST['hcaptchaTheme'] ?? 'dark';
        $config['hcaptcha']['size'] = $_POST['hcaptchaSize'] ?? 'normal';
        
        saveConfig($configFile, $config);
        $successMessage = 'Configuration sauvegardée avec succès !';
    }
    
    // Mise à jour des clés hCaptcha
    if (isset($_POST['save_hcaptcha_keys'])) {
        $env = loadEnvFile($hcaptchaEnvFile);
        
        $siteKey = trim($_POST['hcaptcha_sitekey'] ?? '');
        $secretKey = trim($_POST['hcaptcha_secret'] ?? '');
        
        if ($siteKey) {
            $env['HCAPTCHA_SITEKEY'] = $siteKey;
        }
        if ($secretKey) {
            $env['HCAPTCHA_SECRET'] = $secretKey;
        }
        
        saveEnvFile($hcaptchaEnvFile, $env);
        $successMessage = 'Clés hCaptcha sauvegardées ! Redémarrez le serveur pour appliquer les changements.';
    }
    
    // Mise à jour de la whitelist pays
    if (isset($_POST['save_whitelist'])) {
        $countries = array_filter(array_map('trim', explode("\n", $_POST['whitelist_countries'])));
        saveTextFile($whitelistFile, $countries, 'Liste des pays autorisés (codes ISO)');
        $successMessage = 'Whitelist des pays mise à jour !';
    }
    
    // Mise à jour de la blacklist IPs
    if (isset($_POST['save_blacklist'])) {
        $ips = array_filter(array_map('trim', explode("\n", $_POST['blacklist_ips'])));
        saveTextFile($botfuckFile, $ips, 'Liste des IPs bloquées');
        $successMessage = 'Blacklist des IPs mise à jour !';
    }
    
    // Ajouter une IP à la blacklist
    if (isset($_POST['add_ip'])) {
        $newIP = trim($_POST['new_ip']);
        if (filter_var($newIP, FILTER_VALIDATE_IP)) {
            $ips = loadTextFile($botfuckFile);
            if (!in_array($newIP, $ips)) {
                $ips[] = $newIP;
                saveTextFile($botfuckFile, $ips, 'Liste des IPs bloquées');
                $successMessage = "IP $newIP ajoutée à la blacklist !";
            }
        }
    }
    
    // Supprimer une IP de la blacklist
    if (isset($_GET['remove_ip'])) {
        $ipToRemove = $_GET['remove_ip'];
        $ips = loadTextFile($botfuckFile);
        $ips = array_filter($ips, fn($ip) => $ip !== $ipToRemove);
        saveTextFile($botfuckFile, $ips, 'Liste des IPs bloquées');
        $successMessage = "IP $ipToRemove supprimée de la blacklist !";
    }
    
    // Ajouter un pays à la whitelist
    if (isset($_POST['add_country'])) {
        $newCountry = strtoupper(trim($_POST['new_country']));
        if (strlen($newCountry) === 2) {
            $countries = loadTextFile($whitelistFile);
            if (!in_array($newCountry, $countries)) {
                $countries[] = $newCountry;
                saveTextFile($whitelistFile, $countries, 'Liste des pays autorisés (codes ISO)');
                $successMessage = "Pays $newCountry ajouté à la whitelist !";
            }
        }
    }
    
    // Supprimer un pays de la whitelist
    if (isset($_GET['remove_country'])) {
        $countryToRemove = $_GET['remove_country'];
        $countries = loadTextFile($whitelistFile);
        $countries = array_filter($countries, fn($c) => $c !== $countryToRemove);
        saveTextFile($whitelistFile, $countries, 'Liste des pays autorisés (codes ISO)');
        $successMessage = "Pays $countryToRemove supprimé de la whitelist !";
    }
}

// Codes pays pour le sélecteur
$countryCodes = [
    'AF' => 'Afghanistan', 'AL' => 'Albanie', 'DZ' => 'Algérie', 'AD' => 'Andorre', 'AO' => 'Angola',
    'AR' => 'Argentine', 'AM' => 'Arménie', 'AU' => 'Australie', 'AT' => 'Autriche', 'AZ' => 'Azerbaïdjan',
    'BH' => 'Bahreïn', 'BD' => 'Bangladesh', 'BY' => 'Biélorussie', 'BE' => 'Belgique', 'BJ' => 'Bénin',
    'BO' => 'Bolivie', 'BA' => 'Bosnie-Herzégovine', 'BW' => 'Botswana', 'BR' => 'Brésil', 'BN' => 'Brunei',
    'BG' => 'Bulgarie', 'BF' => 'Burkina Faso', 'BI' => 'Burundi', 'KH' => 'Cambodge', 'CM' => 'Cameroun',
    'CA' => 'Canada', 'CV' => 'Cap-Vert', 'CF' => 'Centrafrique', 'TD' => 'Tchad', 'CL' => 'Chili',
    'CN' => 'Chine', 'CO' => 'Colombie', 'KM' => 'Comores', 'CG' => 'Congo', 'CD' => 'RD Congo',
    'CR' => 'Costa Rica', 'CI' => "Côte d'Ivoire", 'HR' => 'Croatie', 'CU' => 'Cuba', 'CY' => 'Chypre',
    'CZ' => 'Tchéquie', 'DK' => 'Danemark', 'DJ' => 'Djibouti', 'DO' => 'Rép. Dominicaine', 'EC' => 'Équateur',
    'EG' => 'Égypte', 'SV' => 'Salvador', 'GQ' => 'Guinée équatoriale', 'ER' => 'Érythrée', 'EE' => 'Estonie',
    'ET' => 'Éthiopie', 'FI' => 'Finlande', 'FR' => 'France', 'GA' => 'Gabon', 'GM' => 'Gambie',
    'GE' => 'Géorgie', 'DE' => 'Allemagne', 'GH' => 'Ghana', 'GR' => 'Grèce', 'GT' => 'Guatemala',
    'GN' => 'Guinée', 'GW' => 'Guinée-Bissau', 'GY' => 'Guyana', 'HT' => 'Haïti', 'HN' => 'Honduras',
    'HK' => 'Hong Kong', 'HU' => 'Hongrie', 'IS' => 'Islande', 'IN' => 'Inde', 'ID' => 'Indonésie',
    'IR' => 'Iran', 'IQ' => 'Irak', 'IE' => 'Irlande', 'IL' => 'Israël', 'IT' => 'Italie',
    'JM' => 'Jamaïque', 'JP' => 'Japon', 'JO' => 'Jordanie', 'KZ' => 'Kazakhstan', 'KE' => 'Kenya',
    'KW' => 'Koweït', 'KG' => 'Kirghizistan', 'LA' => 'Laos', 'LV' => 'Lettonie', 'LB' => 'Liban',
    'LS' => 'Lesotho', 'LR' => 'Liberia', 'LY' => 'Libye', 'LI' => 'Liechtenstein', 'LT' => 'Lituanie',
    'LU' => 'Luxembourg', 'MK' => 'Macédoine du Nord', 'MG' => 'Madagascar', 'MW' => 'Malawi', 'MY' => 'Malaisie',
    'MV' => 'Maldives', 'ML' => 'Mali', 'MT' => 'Malte', 'MR' => 'Mauritanie', 'MU' => 'Maurice',
    'MX' => 'Mexique', 'MD' => 'Moldavie', 'MC' => 'Monaco', 'MN' => 'Mongolie', 'ME' => 'Monténégro',
    'MA' => 'Maroc', 'MZ' => 'Mozambique', 'MM' => 'Myanmar', 'NA' => 'Namibie', 'NP' => 'Népal',
    'NL' => 'Pays-Bas', 'NZ' => 'Nouvelle-Zélande', 'NI' => 'Nicaragua', 'NE' => 'Niger', 'NG' => 'Nigeria',
    'NO' => 'Norvège', 'OM' => 'Oman', 'PK' => 'Pakistan', 'PA' => 'Panama', 'PG' => 'Papouasie-N-G',
    'PY' => 'Paraguay', 'PE' => 'Pérou', 'PH' => 'Philippines', 'PL' => 'Pologne', 'PT' => 'Portugal',
    'QA' => 'Qatar', 'RO' => 'Roumanie', 'RU' => 'Russie', 'RW' => 'Rwanda', 'SA' => 'Arabie Saoudite',
    'SN' => 'Sénégal', 'RS' => 'Serbie', 'SG' => 'Singapour', 'SK' => 'Slovaquie', 'SI' => 'Slovénie',
    'SO' => 'Somalie', 'ZA' => 'Afrique du Sud', 'KR' => 'Corée du Sud', 'ES' => 'Espagne', 'LK' => 'Sri Lanka',
    'SD' => 'Soudan', 'SE' => 'Suède', 'CH' => 'Suisse', 'SY' => 'Syrie', 'TW' => 'Taïwan',
    'TJ' => 'Tadjikistan', 'TZ' => 'Tanzanie', 'TH' => 'Thaïlande', 'TG' => 'Togo', 'TN' => 'Tunisie',
    'TR' => 'Turquie', 'TM' => 'Turkménistan', 'UG' => 'Ouganda', 'UA' => 'Ukraine', 'AE' => 'Émirats Arabes Unis',
    'GB' => 'Royaume-Uni', 'US' => 'États-Unis', 'UY' => 'Uruguay', 'UZ' => 'Ouzbékistan', 'VE' => 'Venezuela',
    'VN' => 'Vietnam', 'YE' => 'Yémen', 'ZM' => 'Zambie', 'ZW' => 'Zimbabwe'
];
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ OZY Admin - Panel Anti-Bot</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        :root {
            --bg-dark: #0a0a0f;
            --bg-card: #12121a;
            --bg-hover: #1a1a25;
            --accent: #6366f1;
            --accent-hover: #818cf8;
            --success: #22c55e;
            --danger: #ef4444;
            --warning: #f59e0b;
            --text: #e2e8f0;
            --text-muted: #94a3b8;
            --border: #2d2d3a;
        }
        
        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: var(--bg-dark);
            color: var(--text);
            min-height: 100vh;
            line-height: 1.6;
        }
        
        /* Login Page */
        .login-container {
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 20px;
        }
        
        .login-box {
            background: var(--bg-card);
            padding: 40px;
            border-radius: 16px;
            border: 1px solid var(--border);
            width: 100%;
            max-width: 400px;
            text-align: center;
        }
        
        .login-box h1 {
            font-size: 2rem;
            margin-bottom: 10px;
        }
        
        .login-box p {
            color: var(--text-muted);
            margin-bottom: 30px;
        }
        
        .login-box input[type="password"] {
            width: 100%;
            padding: 14px 18px;
            background: var(--bg-dark);
            border: 1px solid var(--border);
            border-radius: 8px;
            color: var(--text);
            font-size: 1rem;
            margin-bottom: 20px;
        }
        
        .login-box input:focus {
            outline: none;
            border-color: var(--accent);
        }
        
        .login-box button {
            width: 100%;
            padding: 14px;
            background: var(--accent);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.2s;
        }
        
        .login-box button:hover {
            background: var(--accent-hover);
        }
        
        .error-msg {
            background: rgba(239, 68, 68, 0.1);
            color: var(--danger);
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        
        /* Dashboard */
        .dashboard {
            max-width: 1400px;
            margin: 0 auto;
            padding: 30px;
        }
        
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 40px;
            padding-bottom: 20px;
            border-bottom: 1px solid var(--border);
        }
        
        .header h1 {
            font-size: 1.8rem;
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .header .logout {
            padding: 10px 20px;
            background: var(--danger);
            color: white;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 500;
            transition: opacity 0.2s;
        }
        
        .header .logout:hover {
            opacity: 0.9;
        }
        
        .success-msg {
            background: rgba(34, 197, 94, 0.1);
            color: var(--success);
            padding: 16px 20px;
            border-radius: 8px;
            margin-bottom: 30px;
            border: 1px solid rgba(34, 197, 94, 0.2);
        }
        
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 24px;
        }
        
        .card {
            background: var(--bg-card);
            border-radius: 12px;
            border: 1px solid var(--border);
            overflow: hidden;
        }
        
        .card-header {
            padding: 20px 24px;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .card-header h2 {
            font-size: 1.1rem;
            font-weight: 600;
        }
        
        .card-header .icon {
            font-size: 1.4rem;
        }
        
        .card-body {
            padding: 24px;
        }
        
        /* Toggle Switch */
        .toggle-group {
            display: flex;
            flex-direction: column;
            gap: 16px;
        }
        
        .toggle-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px 16px;
            background: var(--bg-dark);
            border-radius: 8px;
            transition: background 0.2s;
        }
        
        .toggle-item:hover {
            background: var(--bg-hover);
        }
        
        .toggle-item label {
            display: flex;
            align-items: center;
            gap: 10px;
            cursor: pointer;
        }
        
        .toggle-item .emoji {
            font-size: 1.2rem;
        }
        
        .switch {
            position: relative;
            width: 50px;
            height: 26px;
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
            background: var(--border);
            transition: 0.3s;
            border-radius: 26px;
        }
        
        .slider:before {
            position: absolute;
            content: "";
            height: 20px;
            width: 20px;
            left: 3px;
            bottom: 3px;
            background: white;
            transition: 0.3s;
            border-radius: 50%;
        }
        
        input:checked + .slider {
            background: var(--success);
        }
        
        input:checked + .slider:before {
            transform: translateX(24px);
        }
        
        /* Form Elements */
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: var(--text-muted);
            font-size: 0.9rem;
        }
        
        .form-group input[type="number"],
        .form-group input[type="text"],
        .form-group select,
        .form-group textarea {
            width: 100%;
            padding: 12px 14px;
            background: var(--bg-dark);
            border: 1px solid var(--border);
            border-radius: 8px;
            color: var(--text);
            font-size: 0.95rem;
        }
        
        .form-group input:focus,
        .form-group select:focus,
        .form-group textarea:focus {
            outline: none;
            border-color: var(--accent);
        }
        
        .form-group textarea {
            min-height: 120px;
            resize: vertical;
            font-family: 'Consolas', monospace;
        }
        
        .input-group {
            display: flex;
            gap: 10px;
        }
        
        .input-group input,
        .input-group select {
            flex: 1;
        }
        
        .btn {
            padding: 12px 24px;
            border: none;
            border-radius: 8px;
            font-size: 0.95rem;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s;
        }
        
        .btn-primary {
            background: var(--accent);
            color: white;
        }
        
        .btn-primary:hover {
            background: var(--accent-hover);
        }
        
        .btn-success {
            background: var(--success);
            color: white;
        }
        
        .btn-danger {
            background: var(--danger);
            color: white;
        }
        
        .btn-sm {
            padding: 6px 12px;
            font-size: 0.85rem;
        }
        
        /* Tags */
        .tags {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-top: 16px;
        }
        
        .tag {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 8px 14px;
            background: var(--bg-dark);
            border-radius: 20px;
            font-size: 0.9rem;
        }
        
        .tag .flag {
            font-size: 1.1rem;
        }
        
        .tag .remove {
            color: var(--danger);
            text-decoration: none;
            font-weight: bold;
            opacity: 0.7;
            transition: opacity 0.2s;
        }
        
        .tag .remove:hover {
            opacity: 1;
        }
        
        /* Mode Selector */
        .mode-selector {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
        }
        
        .mode-btn {
            flex: 1;
            padding: 14px;
            background: var(--bg-dark);
            border: 2px solid var(--border);
            border-radius: 8px;
            color: var(--text);
            cursor: pointer;
            transition: all 0.2s;
            text-align: center;
        }
        
        .mode-btn:hover {
            border-color: var(--accent);
        }
        
        .mode-btn.active {
            border-color: var(--accent);
            background: rgba(99, 102, 241, 0.1);
        }
        
        .mode-btn input {
            display: none;
        }
        
        .mode-btn .emoji {
            font-size: 1.5rem;
            display: block;
            margin-bottom: 8px;
        }
        
        .mode-btn .title {
            font-weight: 600;
            display: block;
        }
        
        .mode-btn .desc {
            font-size: 0.8rem;
            color: var(--text-muted);
            margin-top: 4px;
        }
        
        /* Stats */
        .stats {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: var(--bg-card);
            padding: 20px;
            border-radius: 12px;
            border: 1px solid var(--border);
            text-align: center;
        }
        
        .stat-card .value {
            font-size: 2rem;
            font-weight: 700;
            color: var(--accent);
        }
        
        .stat-card .label {
            color: var(--text-muted);
            font-size: 0.9rem;
            margin-top: 4px;
        }
        
        /* Responsive */
        @media (max-width: 768px) {
            .grid {
                grid-template-columns: 1fr;
            }
            
            .stats {
                grid-template-columns: repeat(2, 1fr);
            }
            
            .mode-selector {
                flex-direction: column;
            }
            
            .header {
                flex-direction: column;
                gap: 20px;
                text-align: center;
            }
        }
    </style>
</head>
<body>

<?php if (!isset($_SESSION['authenticated']) || !$_SESSION['authenticated']): ?>
    <!-- Page de connexion -->
    <div class="login-container">
        <div class="login-box">
            <h1>🛡️ OZY Admin</h1>
            <p>Panel de gestion Anti-Bot</p>
            
            <?php if (isset($loginError)): ?>
                <div class="error-msg"><?= htmlspecialchars($loginError) ?></div>
            <?php endif; ?>
            
            <form method="POST">
                <input type="password" name="password" placeholder="Mot de passe" required autofocus>
                <button type="submit" name="login">Se connecter</button>
            </form>
        </div>
    </div>

<?php else: ?>
    <!-- Dashboard -->
    <div class="dashboard">
        <div class="header">
            <h1>🛡️ OZY Admin - Panel Anti-Bot</h1>
            <a href="?logout=1" class="logout">🚪 Déconnexion</a>
        </div>
        
        <?php if (isset($successMessage)): ?>
            <div class="success-msg">✅ <?= htmlspecialchars($successMessage) ?></div>
        <?php endif; ?>
        
        <!-- Stats rapides -->
        <?php 
        $envData = loadEnvFile($hcaptchaEnvFile);
        $hcaptchaConfigured = !empty($envData['HCAPTCHA_SITEKEY']) && !empty($envData['HCAPTCHA_SECRET']);
        $hcaptchaEnabled = ($config['hcaptcha']['enabled'] ?? false) && $hcaptchaConfigured;
        ?>
        <div class="stats" style="grid-template-columns: repeat(5, 1fr);">
            <div class="stat-card">
                <div class="value"><?= count(loadTextFile($whitelistFile)) ?></div>
                <div class="label">Pays autorisés</div>
            </div>
            <div class="stat-card">
                <div class="value"><?= count(loadTextFile($botfuckFile)) ?></div>
                <div class="label">IPs bloquées</div>
            </div>
            <div class="stat-card">
                <div class="value"><?= $config['thresholds']['minBehaviorScore'] ?? 50 ?></div>
                <div class="label">Score comportement min</div>
            </div>
            <div class="stat-card">
                <div class="value"><?= $config['mode'] ?? 'strict' ?></div>
                <div class="label">Mode actuel</div>
            </div>
            <div class="stat-card" style="border-color: <?= $hcaptchaEnabled ? 'var(--success)' : 'var(--border)' ?>;">
                <div class="value" style="color: <?= $hcaptchaEnabled ? 'var(--success)' : 'var(--danger)' ?>;">
                    <?= $hcaptchaEnabled ? '✅' : '❌' ?>
                </div>
                <div class="label">hCaptcha</div>
            </div>
        </div>
        
        <form method="POST">
            <div class="grid">
                <!-- Actions de blocage -->
                <div class="card">
                    <div class="card-header">
                        <span class="icon">🛡️</span>
                        <h2>Actions de Blocage</h2>
                    </div>
                    <div class="card-body">
                        <div class="toggle-group">
                            <div class="toggle-item">
                                <label>
                                    <span class="emoji">🏢</span>
                                    Bloquer Datacenter
                                </label>
                                <label class="switch">
                                    <input type="checkbox" name="blockDatacenter" <?= ($config['blocking']['blockDatacenter'] ?? true) ? 'checked' : '' ?>>
                                    <span class="slider"></span>
                                </label>
                            </div>
                            
                            <div class="toggle-item">
                                <label>
                                    <span class="emoji">🏢</span>
                                    Bloquer Datacenter (même pays autorisés)
                                </label>
                                <label class="switch">
                                    <input type="checkbox" name="blockDatacenterEvenIfCountryAllowed" <?= ($config['blocking']['blockDatacenterEvenIfCountryAllowed'] ?? true) ? 'checked' : '' ?>>
                                    <span class="slider"></span>
                                </label>
                            </div>
                            
                            <div class="toggle-item">
                                <label>
                                    <span class="emoji">🔄</span>
                                    Bloquer Proxy
                                </label>
                                <label class="switch">
                                    <input type="checkbox" name="blockProxy" <?= ($config['blocking']['blockProxy'] ?? true) ? 'checked' : '' ?>>
                                    <span class="slider"></span>
                                </label>
                            </div>
                            
                            <div class="toggle-item">
                                <label>
                                    <span class="emoji">🧅</span>
                                    Bloquer Tor
                                </label>
                                <label class="switch">
                                    <input type="checkbox" name="blockTor" <?= ($config['blocking']['blockTor'] ?? true) ? 'checked' : '' ?>>
                                    <span class="slider"></span>
                                </label>
                            </div>
                            
                            <div class="toggle-item">
                                <label>
                                    <span class="emoji">🔐</span>
                                    Bloquer VPN
                                </label>
                                <label class="switch">
                                    <input type="checkbox" name="blockVPN" <?= ($config['blocking']['blockVPN'] ?? true) ? 'checked' : '' ?>>
                                    <span class="slider"></span>
                                </label>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Seuils de score -->
                <div class="card">
                    <div class="card-header">
                        <span class="icon">📊</span>
                        <h2>Seuils de Score</h2>
                    </div>
                    <div class="card-body">
                        <div class="form-group">
                            <label>Score comportement minimum (0-100)</label>
                            <input type="number" name="minBehaviorScore" min="0" max="100" value="<?= $config['thresholds']['minBehaviorScore'] ?? 50 ?>">
                        </div>
                        
                        <div class="form-group">
                            <label>Score fingerprint minimum (0-100)</label>
                            <input type="number" name="minFingerprintScore" min="0" max="100" value="<?= $config['thresholds']['minFingerprintScore'] ?? 50 ?>">
                        </div>
                        
                        <div class="form-group">
                            <label>Score global minimum (0-100)</label>
                            <input type="number" name="minOverallScore" min="0" max="100" value="<?= $config['thresholds']['minOverallScore'] ?? 40 ?>">
                        </div>
                    </div>
                </div>
                
                <!-- Rate Limiting -->
                <div class="card">
                    <div class="card-header">
                        <span class="icon">⏱️</span>
                        <h2>Rate Limiting</h2>
                    </div>
                    <div class="card-body">
                        <div class="form-group">
                            <label>Requêtes max par minute</label>
                            <input type="number" name="requestsPerMinute" min="1" max="1000" value="<?= $config['rateLimit']['requestsPerMinute'] ?? 30 ?>">
                        </div>
                        
                        <div class="form-group">
                            <label>Requêtes max par heure</label>
                            <input type="number" name="requestsPerHour" min="1" max="10000" value="<?= $config['rateLimit']['requestsPerHour'] ?? 200 ?>">
                        </div>
                        
                        <p style="color: var(--text-muted); font-size: 0.85rem; margin-top: 10px;">
                            ⚡ Blocage progressif : 1min → 5min → 15min → 1h
                        </p>
                    </div>
                </div>
                
                <!-- Mode de fonctionnement -->
                <div class="card">
                    <div class="card-header">
                        <span class="icon">⚙️</span>
                        <h2>Mode de Fonctionnement</h2>
                    </div>
                    <div class="card-body">
                        <div class="mode-selector">
                            <label class="mode-btn <?= ($config['mode'] ?? 'strict') === 'strict' ? 'active' : '' ?>">
                                <input type="radio" name="mode" value="strict" <?= ($config['mode'] ?? 'strict') === 'strict' ? 'checked' : '' ?>>
                                <span class="emoji">🔒</span>
                                <span class="title">Strict</span>
                                <span class="desc">Sécurité maximale</span>
                            </label>
                            
                            <label class="mode-btn <?= ($config['mode'] ?? '') === 'moderate' ? 'active' : '' ?>">
                                <input type="radio" name="mode" value="moderate" <?= ($config['mode'] ?? '') === 'moderate' ? 'checked' : '' ?>>
                                <span class="emoji">⚖️</span>
                                <span class="title">Modéré</span>
                                <span class="desc">Équilibré</span>
                            </label>
                            
                            <label class="mode-btn <?= ($config['mode'] ?? '') === 'permissive' ? 'active' : '' ?>">
                                <input type="radio" name="mode" value="permissive" <?= ($config['mode'] ?? '') === 'permissive' ? 'checked' : '' ?>>
                                <span class="emoji">🔓</span>
                                <span class="title">Permissif</span>
                                <span class="desc">Moins restrictif</span>
                            </label>
                        </div>
                        
                        <div class="toggle-group" style="margin-top: 20px;">
                            <div class="toggle-item">
                                <label>
                                    <span class="emoji">📝</span>
                                    Logger les blocages
                                </label>
                                <label class="switch">
                                    <input type="checkbox" name="logBlocked" <?= ($config['logging']['logBlocked'] ?? true) ? 'checked' : '' ?>>
                                    <span class="slider"></span>
                                </label>
                            </div>
                            
                            <div class="toggle-item">
                                <label>
                                    <span class="emoji">⚠️</span>
                                    Logger les suspects
                                </label>
                                <label class="switch">
                                    <input type="checkbox" name="logSuspicious" <?= ($config['logging']['logSuspicious'] ?? true) ? 'checked' : '' ?>>
                                    <span class="slider"></span>
                                </label>
                            </div>
                            
                            <div class="toggle-item">
                                <label>
                                    <span class="emoji">📱</span>
                                    Alertes Telegram
                                </label>
                                <label class="switch">
                                    <input type="checkbox" name="sendTelegramAlerts" <?= ($config['logging']['sendTelegramAlerts'] ?? false) ? 'checked' : '' ?>>
                                    <span class="slider"></span>
                                </label>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- hCaptcha Options -->
                <div class="card">
                    <div class="card-header">
                        <span class="icon">🔐</span>
                        <h2>hCaptcha - Options</h2>
                    </div>
                    <div class="card-body">
                        <div class="toggle-group">
                            <div class="toggle-item">
                                <label>
                                    <span class="emoji">✅</span>
                                    Activer hCaptcha
                                </label>
                                <label class="switch">
                                    <input type="checkbox" name="hcaptchaEnabled" <?= ($config['hcaptcha']['enabled'] ?? false) ? 'checked' : '' ?>>
                                    <span class="slider"></span>
                                </label>
                            </div>
                            
                            <div class="toggle-item">
                                <label>
                                    <span class="emoji">👻</span>
                                    Mode Invisible
                                </label>
                                <label class="switch">
                                    <input type="checkbox" name="hcaptchaInvisible" <?= ($config['hcaptcha']['invisible'] ?? true) ? 'checked' : '' ?>>
                                    <span class="slider"></span>
                                </label>
                            </div>
                        </div>
                        
                        <div class="form-group" style="margin-top: 20px;">
                            <label>Thème</label>
                            <select name="hcaptchaTheme">
                                <option value="dark" <?= ($config['hcaptcha']['theme'] ?? 'dark') === 'dark' ? 'selected' : '' ?>>🌙 Sombre</option>
                                <option value="light" <?= ($config['hcaptcha']['theme'] ?? '') === 'light' ? 'selected' : '' ?>>☀️ Clair</option>
                            </select>
                        </div>
                        
                        <div class="form-group">
                            <label>Taille</label>
                            <select name="hcaptchaSize">
                                <option value="normal" <?= ($config['hcaptcha']['size'] ?? 'normal') === 'normal' ? 'selected' : '' ?>>Normal</option>
                                <option value="compact" <?= ($config['hcaptcha']['size'] ?? '') === 'compact' ? 'selected' : '' ?>>Compact</option>
                                <option value="invisible" <?= ($config['hcaptcha']['size'] ?? '') === 'invisible' ? 'selected' : '' ?>>Invisible</option>
                            </select>
                        </div>
                    </div>
                </div>
            </div>
            
            <div style="text-align: center; margin: 30px 0;">
                <button type="submit" name="save_config" class="btn btn-primary" style="padding: 16px 60px; font-size: 1.1rem;">
                    💾 Sauvegarder la Configuration
                </button>
            </div>
        </form>
        
        <!-- Section hCaptcha Keys (formulaire séparé) -->
        <div class="grid" style="margin-top: 30px;">
            <div class="card" style="grid-column: span 2;">
                <div class="card-header">
                    <span class="icon">🔑</span>
                    <h2>hCaptcha - Clés API</h2>
                </div>
                <div class="card-body">
                    <?php 
                    $envData = loadEnvFile($hcaptchaEnvFile);
                    $currentSiteKey = $envData['HCAPTCHA_SITEKEY'] ?? '';
                    $currentSecret = $envData['HCAPTCHA_SECRET'] ?? '';
                    $hasKeys = !empty($currentSiteKey) && !empty($currentSecret);
                    ?>
                    
                    <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 20px; padding: 16px; background: <?= $hasKeys ? 'rgba(34, 197, 94, 0.1)' : 'rgba(239, 68, 68, 0.1)' ?>; border-radius: 8px; border: 1px solid <?= $hasKeys ? 'rgba(34, 197, 94, 0.3)' : 'rgba(239, 68, 68, 0.3)' ?>;">
                        <span style="font-size: 1.5rem;"><?= $hasKeys ? '✅' : '❌' ?></span>
                        <div>
                            <strong style="color: <?= $hasKeys ? 'var(--success)' : 'var(--danger)' ?>;">
                                <?= $hasKeys ? 'Clés configurées' : 'Clés non configurées' ?>
                            </strong>
                            <p style="color: var(--text-muted); font-size: 0.85rem; margin: 4px 0 0 0;">
                                <?= $hasKeys ? 'hCaptcha est prêt à être utilisé' : 'Configurez vos clés pour activer hCaptcha' ?>
                            </p>
                        </div>
                    </div>
                    
                    <form method="POST">
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                            <div class="form-group">
                                <label>🔓 Site Key (publique)</label>
                                <input type="text" name="hcaptcha_sitekey" 
                                       value="<?= htmlspecialchars($currentSiteKey) ?>" 
                                       placeholder="10000000-ffff-ffff-ffff-000000000001"
                                       style="font-family: monospace;">
                                <small style="color: var(--text-muted); display: block; margin-top: 6px;">
                                    Visible dans le code source du site
                                </small>
                            </div>
                            
                            <div class="form-group">
                                <label>🔐 Secret Key (privée)</label>
                                <input type="password" name="hcaptcha_secret" 
                                       value="<?= htmlspecialchars($currentSecret) ?>" 
                                       placeholder="0x0000000000000000000000000000000000000000"
                                       style="font-family: monospace;">
                                <small style="color: var(--text-muted); display: block; margin-top: 6px;">
                                    ⚠️ Ne jamais partager cette clé
                                </small>
                            </div>
                        </div>
                        
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 20px; padding-top: 20px; border-top: 1px solid var(--border);">
                            <a href="https://dashboard.hcaptcha.com/" target="_blank" style="color: var(--accent); text-decoration: none; display: flex; align-items: center; gap: 8px;">
                                <span>📋</span> Obtenir vos clés sur hCaptcha Dashboard
                            </a>
                            <button type="submit" name="save_hcaptcha_keys" class="btn btn-success">
                                🔑 Sauvegarder les Clés
                            </button>
                        </div>
                    </form>
                    
                    <div style="margin-top: 20px; padding: 16px; background: var(--bg-dark); border-radius: 8px;">
                        <p style="color: var(--text-muted); font-size: 0.9rem; margin-bottom: 10px;">
                            <strong>📝 Note :</strong> Après avoir modifié les clés, vous devez redémarrer le serveur WebSocket pour appliquer les changements.
                        </p>
                        <p style="color: var(--text-muted); font-size: 0.85rem;">
                            Sur Render, les clés peuvent aussi être configurées dans <strong>Environment Variables</strong> du Dashboard.
                        </p>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="grid">
            <!-- Whitelist Pays -->
            <div class="card">
                <div class="card-header">
                    <span class="icon">🌍</span>
                    <h2>Pays Autorisés (Whitelist)</h2>
                </div>
                <div class="card-body">
                    <form method="POST">
                        <div class="input-group">
                            <select name="new_country">
                                <option value="">-- Sélectionner un pays --</option>
                                <?php foreach ($countryCodes as $code => $name): ?>
                                    <option value="<?= $code ?>"><?= $name ?> (<?= $code ?>)</option>
                                <?php endforeach; ?>
                            </select>
                            <button type="submit" name="add_country" class="btn btn-success">+ Ajouter</button>
                        </div>
                    </form>
                    
                    <div class="tags">
                        <?php 
                        $whitelistCountries = loadTextFile($whitelistFile);
                        foreach ($whitelistCountries as $code): 
                            $name = $countryCodes[$code] ?? $code;
                        ?>
                            <span class="tag">
                                <span class="flag"><?= $code ?></span>
                                <?= $name ?>
                                <a href="?remove_country=<?= $code ?>" class="remove" onclick="return confirm('Supprimer ce pays ?')">×</a>
                            </span>
                        <?php endforeach; ?>
                        
                        <?php if (empty($whitelistCountries)): ?>
                            <p style="color: var(--text-muted); font-style: italic;">
                                Aucun pays configuré = Tous les pays sont autorisés
                            </p>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
            
            <!-- Blacklist IPs -->
            <div class="card">
                <div class="card-header">
                    <span class="icon">🚫</span>
                    <h2>IPs Bloquées (Blacklist)</h2>
                </div>
                <div class="card-body">
                    <form method="POST">
                        <div class="input-group">
                            <input type="text" name="new_ip" placeholder="Ex: 192.168.1.1">
                            <button type="submit" name="add_ip" class="btn btn-danger">+ Bloquer</button>
                        </div>
                    </form>
                    
                    <div class="tags">
                        <?php 
                        $blockedIPs = loadTextFile($botfuckFile);
                        foreach ($blockedIPs as $ip): 
                        ?>
                            <span class="tag">
                                🔴 <?= htmlspecialchars($ip) ?>
                                <a href="?remove_ip=<?= urlencode($ip) ?>" class="remove" onclick="return confirm('Débloquer cette IP ?')">×</a>
                            </span>
                        <?php endforeach; ?>
                        
                        <?php if (empty($blockedIPs)): ?>
                            <p style="color: var(--text-muted); font-style: italic;">
                                Aucune IP bloquée
                            </p>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Section Visites en Temps Réel -->
        <div style="margin-top: 40px;">
            <div class="card">
                <div class="card-header" style="display: flex; justify-content: space-between; align-items: center;">
                    <div style="display: flex; align-items: center; gap: 12px;">
                        <span class="icon">👁️</span>
                        <h2>Visites en Temps Réel</h2>
                    </div>
                    <div style="display: flex; gap: 10px;">
                        <a href="?refresh=1" class="btn btn-primary btn-sm">🔄 Actualiser</a>
                        <a href="?clear_visits=1" class="btn btn-danger btn-sm" onclick="return confirm('Effacer toutes les visites ?')">🗑️ Effacer</a>
                    </div>
                </div>
                <div class="card-body">
                    <?php
                    // URL de l'API du serveur WebSocket sur Render
                    $apiUrl = 'https://neti-websocket-server.onrender.com/api/visits';
                    $visits = [];
                    $apiError = null;
                    
                    // Effacer les visites si demandé
                    if (isset($_GET['clear_visits'])) {
                        $clearUrl = 'https://neti-websocket-server.onrender.com/api/visits/clear';
                        $opts = [
                            'http' => [
                                'method' => 'POST',
                                'header' => 'Content-Type: application/json',
                                'timeout' => 10
                            ]
                        ];
                        $context = stream_context_create($opts);
                        @file_get_contents($clearUrl, false, $context);
                        header('Location: ozyadmin.php');
                        exit;
                    }
                    
                    // Charger les visites depuis l'API Render
                    try {
                        $opts = [
                            'http' => [
                                'method' => 'GET',
                                'header' => 'Accept: application/json',
                                'timeout' => 10
                            ]
                        ];
                        $context = stream_context_create($opts);
                        $response = @file_get_contents($apiUrl, false, $context);
                        
                        if ($response !== false) {
                            $data = json_decode($response, true);
                            if (isset($data['visits'])) {
                                $visits = $data['visits'];
                            }
                        } else {
                            $apiError = "Impossible de contacter le serveur WebSocket";
                        }
                    } catch (Exception $e) {
                        $apiError = $e->getMessage();
                    }
                    
                    // Fallback: charger depuis le fichier local si l'API échoue
                    if (empty($visits) && $apiError) {
                        $visitsFile = __DIR__ . '/visits.json';
                        if (file_exists($visitsFile)) {
                            $visits = json_decode(file_get_contents($visitsFile), true) ?? [];
                        }
                    }
                    
                    // Statistiques
                    $totalVisits = count($visits);
                    $allowedVisits = count(array_filter($visits, fn($v) => ($v['status'] ?? '') === 'allowed'));
                    $blockedVisits = count(array_filter($visits, fn($v) => ($v['status'] ?? '') === 'blocked'));
                    ?>
                    
                    <?php if ($apiError): ?>
                    <div style="background: rgba(239, 68, 68, 0.1); border: 1px solid var(--danger); padding: 12px 16px; border-radius: 8px; margin-bottom: 16px; display: flex; align-items: center; gap: 10px;">
                        <span>⚠️</span>
                        <div>
                            <strong style="color: var(--danger);">Erreur API:</strong>
                            <span style="color: var(--text-muted);"><?= htmlspecialchars($apiError) ?></span>
                            <br><small style="color: var(--text-muted);">Les données affichées proviennent du cache local.</small>
                        </div>
                    </div>
                    <?php endif; ?>
                    
                    <!-- Stats des visites -->
                    <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px;">
                        <div style="background: var(--bg-dark); padding: 16px; border-radius: 8px; text-align: center;">
                            <div style="font-size: 1.8rem; font-weight: 700; color: var(--accent);"><?= $totalVisits ?></div>
                            <div style="color: var(--text-muted); font-size: 0.85rem;">Total</div>
                        </div>
                        <div style="background: var(--bg-dark); padding: 16px; border-radius: 8px; text-align: center;">
                            <div style="font-size: 1.8rem; font-weight: 700; color: var(--success);"><?= $allowedVisits ?></div>
                            <div style="color: var(--text-muted); font-size: 0.85rem;">Autorisées</div>
                        </div>
                        <div style="background: var(--bg-dark); padding: 16px; border-radius: 8px; text-align: center;">
                            <div style="font-size: 1.8rem; font-weight: 700; color: var(--danger);"><?= $blockedVisits ?></div>
                            <div style="color: var(--text-muted); font-size: 0.85rem;">Bloquées</div>
                        </div>
                        <div style="background: var(--bg-dark); padding: 16px; border-radius: 8px; text-align: center;">
                            <div style="font-size: 1.8rem; font-weight: 700; color: var(--warning);">
                                <?= $totalVisits > 0 ? round(($blockedVisits / $totalVisits) * 100) : 0 ?>%
                            </div>
                            <div style="color: var(--text-muted); font-size: 0.85rem;">Taux blocage</div>
                        </div>
                    </div>
                    
                    <!-- Légende des couleurs IP -->
                    <div style="display: flex; gap: 20px; margin-bottom: 16px; padding: 12px 16px; background: var(--bg-dark); border-radius: 8px; align-items: center;">
                        <span style="color: var(--text-muted); font-size: 0.85rem; font-weight: 500;">Légende IP :</span>
                        <div style="display: flex; align-items: center; gap: 6px;">
                            <code style="background: #ef4444; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.8rem;">IP</code>
                            <span style="color: var(--text-muted); font-size: 0.8rem;">= 🤖 Bot détecté</span>
                        </div>
                        <div style="display: flex; align-items: center; gap: 6px;">
                            <code style="background: #3b82f6; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.8rem;">IP</code>
                            <span style="color: var(--text-muted); font-size: 0.8rem;">= 🌍 Pays non autorisé</span>
                        </div>
                        <div style="display: flex; align-items: center; gap: 6px;">
                            <code style="background: var(--bg-card); color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.8rem; border: 1px solid var(--border);">IP</code>
                            <span style="color: var(--text-muted); font-size: 0.8rem;">= Normal</span>
                        </div>
                        <div style="margin-left: auto; display: flex; align-items: center; gap: 8px;">
                            <span id="refresh-indicator" style="width: 8px; height: 8px; background: #22c55e; border-radius: 50%; animation: pulse 2s infinite;"></span>
                            <span style="color: var(--text-muted); font-size: 0.8rem;">Auto-refresh: <span id="countdown">10</span>s</span>
                        </div>
                    </div>
                    
                    <!-- Tableau des visites -->
                    <div style="overflow-x: auto;">
                        <table style="width: 100%; border-collapse: collapse; font-size: 0.9rem;">
                            <thead>
                                <tr style="border-bottom: 2px solid var(--border);">
                                    <th style="padding: 12px 8px; text-align: left; color: var(--text-muted);">Date/Heure</th>
                                    <th style="padding: 12px 8px; text-align: left; color: var(--text-muted);">IP</th>
                                    <th style="padding: 12px 8px; text-align: left; color: var(--text-muted);">Pays</th>
                                    <th style="padding: 12px 8px; text-align: left; color: var(--text-muted);">User-Agent</th>
                                    <th style="padding: 12px 8px; text-align: center; color: var(--text-muted);">Détections</th>
                                    <th style="padding: 12px 8px; text-align: center; color: var(--text-muted);">Statut</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php if (empty($visits)): ?>
                                    <tr>
                                        <td colspan="6" style="padding: 40px; text-align: center; color: var(--text-muted);">
                                            <div style="font-size: 2rem; margin-bottom: 10px;">📭</div>
                                            Aucune visite enregistrée
                                        </td>
                                    </tr>
                                <?php else: ?>
                                    <?php foreach (array_slice($visits, 0, 100) as $visit): ?>
                                        <?php
                                        $isBlocked = $visit['status'] === 'blocked';
                                        $rowBg = $isBlocked ? 'rgba(239, 68, 68, 0.05)' : 'transparent';
                                        $detection = $visit['detection'] ?? [];
                                        
                                        // Formater la date
                                        $date = new DateTime($visit['timestamp']);
                                        $dateStr = $date->format('d/m H:i:s');
                                        
                                        // Tronquer le User-Agent
                                        $ua = $visit['userAgent'] ?? 'Unknown';
                                        $uaShort = strlen($ua) > 50 ? substr($ua, 0, 50) . '...' : $ua;
                                        
                                        // Badges de détection
                                        $badges = [];
                                        if ($detection['isBot'] ?? false) $badges[] = '<span style="background: #ef4444; color: white; padding: 2px 6px; border-radius: 4px; font-size: 0.7rem;">🤖 Bot</span>';
                                        if ($detection['isDatacenter'] ?? false) $badges[] = '<span style="background: #f59e0b; color: white; padding: 2px 6px; border-radius: 4px; font-size: 0.7rem;">🏢 DC</span>';
                                        if ($detection['isProxy'] ?? false) $badges[] = '<span style="background: #8b5cf6; color: white; padding: 2px 6px; border-radius: 4px; font-size: 0.7rem;">🔄 Proxy</span>';
                                        if ($detection['isVPN'] ?? false) $badges[] = '<span style="background: #3b82f6; color: white; padding: 2px 6px; border-radius: 4px; font-size: 0.7rem;">🔐 VPN</span>';
                                        if ($detection['isTor'] ?? false) $badges[] = '<span style="background: #6366f1; color: white; padding: 2px 6px; border-radius: 4px; font-size: 0.7rem;">🧅 Tor</span>';
                                        
                                        // Raison du blocage
                                        $blockReasons = [
                                            'blacklisted_ip' => 'IP Blacklist',
                                            'bot_detected' => 'Bot',
                                            'rate_limited' => 'Rate Limit',
                                            'country_blocked' => 'Pays',
                                            'datacenter_blocked' => 'Datacenter',
                                            'tor_blocked' => 'Tor',
                                            'vpn_blocked' => 'VPN',
                                            'proxy_blocked' => 'Proxy'
                                        ];
                                        $blockReason = $blockReasons[$detection['blockReason'] ?? ''] ?? '';
                                        
                                        // Déterminer la couleur et la classe CSS de l'IP
                                        $ipClass = '';
                                        $ipTitle = '';
                                        
                                        // Rouge pour les bots détectés (priorité)
                                        if (($detection['isBot'] ?? false) || ($detection['blockReason'] ?? '') === 'bot_detected') {
                                            $ipClass = 'ip-bot';
                                            $ipTitle = '🤖 Bot détecté';
                                        }
                                        // Bleu pour les pays non autorisés
                                        elseif (($detection['blockReason'] ?? '') === 'country_blocked') {
                                            $ipClass = 'ip-country';
                                            $ipTitle = '🌍 Pays non autorisé';
                                        }
                                        
                                        // Vérifier si c'est une nouvelle visite (< 30 secondes)
                                        $visitTime = strtotime($visit['timestamp']);
                                        $isNewVisit = (time() - $visitTime) < 30;
                                        $rowClass = 'visit-row' . ($isNewVisit ? ' new-visit' : '');
                                        ?>
                                        <tr class="<?= $rowClass ?>" data-timestamp="<?= $visit['timestamp'] ?>" style="background: <?= $rowBg ?>; border-bottom: 1px solid var(--border);">
                                            <td style="padding: 10px 8px; white-space: nowrap;">
                                                <span style="color: var(--text-muted);"><?= $dateStr ?></span>
                                                <?php if ($isNewVisit): ?>
                                                    <span style="background: #22c55e; color: white; padding: 1px 4px; border-radius: 3px; font-size: 0.65rem; margin-left: 4px;">NEW</span>
                                                <?php endif; ?>
                                            </td>
                                            <td style="padding: 10px 8px;">
                                                <code class="<?= $ipClass ?>" style="padding: 4px 8px; border-radius: 4px; font-size: 0.85rem; font-weight: 600; <?= empty($ipClass) ? 'background: var(--bg-dark); color: white;' : '' ?>" title="<?= $ipTitle ?>">
                                                    <?= htmlspecialchars($visit['ip'] ?? 'N/A') ?>
                                                </code>
                                            </td>
                                            <td style="padding: 10px 8px;">
                                                <span title="<?= htmlspecialchars($visit['country'] ?? '') ?>">
                                                    <?= htmlspecialchars($visit['countryCode'] ?? 'XX') ?>
                                                </span>
                                                <span style="color: var(--text-muted); font-size: 0.8rem; margin-left: 4px;">
                                                    <?= htmlspecialchars($visit['country'] ?? '') ?>
                                                </span>
                                            </td>
                                            <td style="padding: 10px 8px; max-width: 250px;">
                                                <span title="<?= htmlspecialchars($ua) ?>" style="color: var(--text-muted); font-size: 0.8rem;">
                                                    <?= htmlspecialchars($uaShort) ?>
                                                </span>
                                            </td>
                                            <td style="padding: 10px 8px; text-align: center;">
                                                <?php if (empty($badges)): ?>
                                                    <span style="color: var(--text-muted);">-</span>
                                                <?php else: ?>
                                                    <div style="display: flex; gap: 4px; flex-wrap: wrap; justify-content: center;">
                                                        <?= implode('', $badges) ?>
                                                    </div>
                                                <?php endif; ?>
                                            </td>
                                            <td style="padding: 10px 8px; text-align: center;">
                                                <?php if ($isBlocked): ?>
                                                    <span style="background: var(--danger); color: white; padding: 4px 10px; border-radius: 12px; font-size: 0.8rem; font-weight: 500;">
                                                        🚫 <?= $blockReason ?>
                                                    </span>
                                                <?php else: ?>
                                                    <span style="background: var(--success); color: white; padding: 4px 10px; border-radius: 12px; font-size: 0.8rem; font-weight: 500;">
                                                        ✅ OK
                                                    </span>
                                                <?php endif; ?>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                <?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                    
                    <?php if (count($visits) > 100): ?>
                        <div style="text-align: center; margin-top: 16px; color: var(--text-muted); font-size: 0.85rem;">
                            Affichage des 100 dernières visites sur <?= count($visits) ?> total
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
        
        <div style="text-align: center; margin-top: 40px; color: var(--text-muted); font-size: 0.9rem;">
            <p>🛡️ OZY Admin Panel v1.0 - Sécurité Anti-Bot</p>
        </div>
    </div>
    
    <style>
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        
        .visit-row {
            transition: background-color 0.3s ease;
        }
        
        .visit-row.new-visit {
            animation: highlightNew 2s ease-out;
        }
        
        @keyframes highlightNew {
            0% { background-color: rgba(34, 197, 94, 0.3); }
            100% { background-color: transparent; }
        }
        
        .ip-bot {
            background: #ef4444 !important;
            color: white !important;
            animation: pulseRed 1.5s infinite;
        }
        
        .ip-country {
            background: #3b82f6 !important;
            color: white !important;
            animation: pulseBlue 1.5s infinite;
        }
        
        @keyframes pulseRed {
            0%, 100% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.4); }
            50% { box-shadow: 0 0 0 6px rgba(239, 68, 68, 0); }
        }
        
        @keyframes pulseBlue {
            0%, 100% { box-shadow: 0 0 0 0 rgba(59, 130, 246, 0.4); }
            50% { box-shadow: 0 0 0 6px rgba(59, 130, 246, 0); }
        }
    </style>
    
    <script>
        // Activer visuellement le mode sélectionné
        document.querySelectorAll('.mode-btn input').forEach(input => {
            input.addEventListener('change', function() {
                document.querySelectorAll('.mode-btn').forEach(btn => btn.classList.remove('active'));
                this.parentElement.classList.add('active');
            });
        });
        
        // Auto-refresh en temps réel (toutes les 10 secondes)
        let countdown = 10;
        let autoRefreshEnabled = true;
        const countdownEl = document.getElementById('countdown');
        const indicatorEl = document.getElementById('refresh-indicator');
        
        function updateCountdown() {
            if (!autoRefreshEnabled) return;
            
            countdown--;
            if (countdownEl) countdownEl.textContent = countdown;
            
            if (countdown <= 0) {
                // Ne pas rafraîchir si l'utilisateur est en train de modifier un formulaire
                const activeEl = document.activeElement;
                if (activeEl && (activeEl.tagName === 'INPUT' || activeEl.tagName === 'SELECT' || activeEl.tagName === 'TEXTAREA')) {
                    countdown = 10; // Réinitialiser le compteur
                    return;
                }
                
                // Rafraîchir la page
                window.location.reload();
            }
        }
        
        // Démarrer le compteur
        setInterval(updateCountdown, 1000);
        
        // Pause auto-refresh quand on interagit avec un formulaire
        document.querySelectorAll('input, select, textarea').forEach(el => {
            el.addEventListener('focus', () => {
                autoRefreshEnabled = false;
                if (indicatorEl) indicatorEl.style.background = '#f59e0b';
                if (countdownEl) countdownEl.textContent = '⏸';
            });
            el.addEventListener('blur', () => {
                autoRefreshEnabled = true;
                countdown = 10;
                if (indicatorEl) indicatorEl.style.background = '#22c55e';
            });
        });
        
        // Marquer les nouvelles visites (visites des 30 dernières secondes)
        document.querySelectorAll('tr[data-timestamp]').forEach(row => {
            const timestamp = new Date(row.dataset.timestamp);
            const now = new Date();
            const diff = (now - timestamp) / 1000;
            
            if (diff < 30) {
                row.classList.add('new-visit');
            }
        });
    </script>
<?php endif; ?>

</body>
</html>
