<?php
// Enable error reporting for debugging
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Start session
session_start();

// Simple error handler to display errors
function handleError($errno, $errstr, $errfile, $errline) {
    if (ini_get('display_errors')) {
        echo "<div class='alert alert-danger'><strong>Error:</strong> $errstr in $errfile on line $errline</div>";
    }
    error_log("Error: $errstr in $errfile on line $errline");
    return true;
}
set_error_handler("handleError");

// Check if required files exist
$required_files = ['includes/config.php', 'includes/functions.php'];
foreach ($required_files as $file) {
    if (!file_exists($file)) {
        die("<div class='alert alert-danger' style='padding: 20px; margin: 20px;'><strong>Error:</strong> Missing required file: $file</div>");
    }
}

// Include required files
require_once 'includes/config.php';
require_once 'includes/functions.php';

// Check if user is logged in
if (!function_exists('isLoggedIn') || !isLoggedIn()) {
    if (function_exists('redirect')) {
        redirect('login.php');
    } else {
        header("Location: login.php");
        exit();
    }
}

// Get user information from session
$user_id = $_SESSION['user_id'] ?? 0;
$user_name = $_SESSION['user_name'] ?? 'User';
$user_email = $_SESSION['user_email'] ?? '';
$user_plan = $_SESSION['user_plan'] ?? 'none';

// Get user plan limits
if (function_exists('getUserPlanLimits')) {
    $planLimits = getUserPlanLimits($user_plan);
    $maxDomains = getMaxDomainsForPlan($user_plan);
} else {
    $planLimits = ['max_domains' => 0, 'features' => []];
    $maxDomains = 0;
}

// Initialize variables
$stats = [
    'total_requests' => 0,
    'blocked_requests' => 0,
    'banned_ips' => 0,
    'allowed_ips' => 0,
    'active_sessions' => 0
];

$activities = [];
$domains = [];
$api_keys = [];
$error = '';
$activeTab = $_GET['tab'] ?? 'dashboard';
$apiOnline = false;
$apiKey = $_SESSION['api_key'] ?? null;

// Only fetch API data if user has a paid plan
if ($user_plan !== 'none' && function_exists('callProtectionAPI')) {
    try {
        // First check if API is online with a simple connection test
        if (function_exists('checkAPIStatus')) {
            $apiOnline = checkAPIStatus();
        } else {
            $apiOnline = false;
        }
        
        if ($apiOnline) {
            // Reset API key generation attempt if we don't have an API key
            if (empty($_SESSION['api_key']) && isset($_SESSION['api_key_generation_attempted'])) {
                unset($_SESSION['api_key_generation_attempted']);
            }
            
            // Only try to get data if we have an API key or can generate one
            $hasValidApiKey = !empty($_SESSION['api_key']) || (function_exists('ensureAPIKey') && ensureAPIKey());
            
            if ($hasValidApiKey) {
                // Always get stats for overview tab
                try {
                    $statsResponse = callProtectionAPI('GET', '/api/protection/stats');
                    if ($statsResponse && isset($statsResponse['total_requests'])) {
                        $stats = $statsResponse;
                    }
                } catch (Exception $e) {
                    error_log("Failed to get stats: " . $e->getMessage());
                    if (strpos($e->getMessage(), 'Invalid API key') !== false) {
                        unset($_SESSION['api_key']);
                    }
                }
                
                // Only load activities if we're on the activity tab
                if ($activeTab === 'activity') {
                    try {
                        $activitiesResponse = callProtectionAPI('GET', '/api/protection/activity?limit=10');
                        if ($activitiesResponse && isset($activitiesResponse['activities'])) {
                            $activities = $activitiesResponse['activities'];
                        }
                    } catch (Exception $e) {
                        error_log("Failed to get activities: " . $e->getMessage());
                        if (strpos($e->getMessage(), 'Invalid API key') !== false) {
                            unset($_SESSION['api_key']);
                        }
                    }
                }
                
                // Always load domains for domain count and protection tab
                if (canUserAccessFeature($user_plan, 'protection')) {
                    try {
                        // SECURITY FIX: Pass user_id to only get domains for this user
                        $domainsResponse = callProtectionAPI('GET', '/api/domains?user_id=' . $user_id);
                        if ($domainsResponse && isset($domainsResponse['domains'])) {
                            $domains = $domainsResponse['domains'];
                        }
                    } catch (Exception $e) {
                        error_log("Failed to get domains: " . $e->getMessage());
                        if (strpos($e->getMessage(), 'Invalid API key') !== false) {
                            unset($_SESSION['api_key']);
                        }
                    }
                }
                
                // Only load API keys if we're on the settings tab
                if ($activeTab === 'settings') {
                    if (canUserAccessFeature($user_plan, 'api_access')) {
                        try {
                            $apiKeysResponse = callProtectionAPI('GET', '/api/api_keys');
                            if ($apiKeysResponse && isset($apiKeysResponse['api_keys'])) {
                                $api_keys = $apiKeysResponse['api_keys'];
                            }
                        } catch (Exception $e) {
                            error_log("Failed to get API keys: " . $e->getMessage());
                            if (strpos($e->getMessage(), 'Invalid API key') !== false) {
                                unset($_SESSION['api_key']);
                            }
                        }
                    }
                }
            } else {
                $error = "Unable to generate API key. Please try generating one manually in the Settings tab.";
            }
        } else {
            $error = "Unable to connect to protection service. Please check if the API server is running.";
        }
    } catch (Exception $e) {
        $error = "API Error: " . $e->getMessage();
        $apiOnline = false;
    }
}

// Handle form submissions only if user has appropriate plan
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $user_plan !== 'none') {
    $action = $_POST['action'] ?? '';
    
    try {
        // Ensure we have an API key before making requests
        ensureAPIKey();
        
        switch ($action) {
            case 'ban_ip':
                if (!canUserAccessFeature($user_plan, 'protection')) {
                    $_SESSION['error'] = "Your plan doesn't include IP management features";
                    break;
                }
                
                $ip = filter_var($_POST['ip'], FILTER_VALIDATE_IP);
                $reason = htmlspecialchars($_POST['reason'] ?? 'Manual ban from dashboard');
                
                if ($ip) {
                    $response = callProtectionAPI('POST', '/api/protection/configure', [
                        'action' => 'ban_ip',
                        'target' => $ip,
                        'value' => $reason
                    ]);
                    
                    if ($response && $response['success']) {
                        $_SESSION['success'] = "IP $ip banned successfully";
                    } else {
                        $_SESSION['error'] = "Failed to ban IP: " . ($response['message'] ?? 'Unknown error');
                    }
                }
                break;
                
            case 'allow_ip':
                if (!canUserAccessFeature($user_plan, 'protection')) {
                    $_SESSION['error'] = "Your plan doesn't include IP management features";
                    break;
                }
                
                $ip = filter_var($_POST['ip'], FILTER_VALIDATE_IP);
                $note = htmlspecialchars($_POST['note'] ?? 'Added from dashboard');
                
                if ($ip) {
                    $response = callProtectionAPI('POST', '/api/protection/configure', [
                        'action' => 'allow_ip',
                        'target' => $ip,
                        'value' => $note
                    ]);
                    
                    if ($response && $response['success']) {
                        $_SESSION['success'] = "IP $ip added to allowlist";
                    } else {
                        $_SESSION['error'] = "Failed to allow IP: " . ($response['message'] ?? 'Unknown error');
                    }
                }
                break;
                
            case 'add_domain':
                if (!canUserAccessFeature($user_plan, 'protection')) {
                    $_SESSION['error'] = "Your plan doesn't include domain protection";
                    break;
                }
                
                $domain = filter_var($_POST['domain'], FILTER_SANITIZE_URL);
                $target_website = filter_var($_POST['target_website'], FILTER_SANITIZE_URL);
                
                // Validate domain format
                if (!preg_match('/^(?!\-)(?:[a-zA-Z\d\-]{0,62}[a-zA-Z\d]\.){1,126}(?!\d+)[a-zA-Z\d]{1,63}$/', $domain)) {
                    $_SESSION['error'] = "Please enter a valid domain name";
                    break;
                }
                
                // First get current domains to check limit
                try {
                    $currentDomainsResponse = callProtectionAPI('GET', '/api/domains?user_id=' . $user_id);
                    $currentDomains = $currentDomainsResponse && isset($currentDomainsResponse['domains']) ? count($currentDomainsResponse['domains']) : 0;
                    
                    // Check domain limit
                    if ($maxDomains !== -1 && $currentDomains >= $maxDomains) {
                        $_SESSION['error'] = "You've reached the maximum limit of $maxDomains domains for your plan";
                        break;
                    }
                } catch (Exception $e) {
                    $_SESSION['error'] = "Failed to check domain limit: " . $e->getMessage();
                    break;
                }
                
                if ($domain && $target_website) {
                    // SECURITY FIX: Pass user_id when adding domain
                    $response = callProtectionAPI('POST', '/api/add_domain', [
                        'domain' => $domain,
                        'target_website' => $target_website,
                        'user_id' => $user_id  // Associate domain with this user
                    ]);
                    
                    if ($response && $response['success']) {
                        $_SESSION['success'] = "Domain $domain added successfully";
                        // Refresh domains list
                        $domainsResponse = callProtectionAPI('GET', '/api/domains?user_id=' . $user_id);
                        if ($domainsResponse && isset($domainsResponse['domains'])) {
                            $domains = $domainsResponse['domains'];
                        }
                    } else {
                        $_SESSION['error'] = "Failed to add domain: " . ($response['message'] ?? 'Unknown error');
                    }
                }
                break;
                
            case 'toggle_protection':
                if (!canUserAccessFeature($user_plan, 'protection')) {
                    $_SESSION['error'] = "Your plan doesn't include protection features";
                    break;
                }
                
                $domainId = $_POST['domain_id'] ?? '';
                $enabled = $_POST['enabled'] ?? '';
                
                if ($domainId) {
                    // SECURITY FIX: Verify domain ownership before toggling protection
                    $domainOwned = false;
                    foreach ($domains as $domain) {
                        if ($domain['id'] == $domainId) {
                            $domainOwned = true;
                            break;
                        }
                    }
                    
                    if (!$domainOwned) {
                        $_SESSION['error'] = "You don't have permission to modify this domain";
                        break;
                    }
                    
                    $response = callProtectionAPI('POST', '/api/toggle_protection', [
                        'domain_id' => $domainId,
                        'enabled' => $enabled
                    ]);
                    
                    if ($response && $response['success']) {
                        $_SESSION['success'] = "Protection " . ($enabled ? 'enabled' : 'disabled') . " successfully";
                        // Refresh domains list
                        $domainsResponse = callProtectionAPI('GET', '/api/domains?user_id=' . $user_id);
                        if ($domainsResponse && isset($domainsResponse['domains'])) {
                            $domains = $domainsResponse['domains'];
                        }
                    } else {
                        $_SESSION['error'] = "Failed to update protection: " . ($response['message'] ?? 'Unknown error');
                    }
                }
                break;
                
            case 'generate_api_key':
                if (!canUserAccessFeature($user_plan, 'api_access')) {
                    $_SESSION['error'] = "Your plan doesn't include API access";
                    break;
                }
                
                $note = htmlspecialchars($_POST['note'] ?? 'Generated from dashboard');
                
                $response = callProtectionAPI('POST', '/api/generate_api_key', [
                    'note' => $note
                ]);
                
                if ($response && $response['success']) {
                    $_SESSION['api_key'] = $response['api_key'];
                    $_SESSION['success'] = "New API key generated successfully";
                    
                    // Refresh API keys list
                    $apiKeysResponse = callProtectionAPI('GET', '/api/api_keys');
                    if ($apiKeysResponse && isset($apiKeysResponse['api_keys'])) {
                        $api_keys = $apiKeysResponse['api_keys'];
                    }
                } else {
                    $_SESSION['error'] = "Failed to generate API key: " . ($response['message'] ?? 'Unknown error');
                }
                break;
                
            case 'delete_api_key':
                if (!canUserAccessFeature($user_plan, 'api_access')) {
                    $_SESSION['error'] = "Your plan doesn't include API access";
                    break;
                }
                
                $key_to_delete = $_POST['api_key'] ?? '';
                
                if ($key_to_delete) {
                    $response = callProtectionAPI('DELETE', '/api/delete_api_key/' . urlencode($key_to_delete));
                    
                    if ($response && $response['success']) {
                        $_SESSION['success'] = "API key deleted successfully";
                        
                        // Refresh API keys list
                        $apiKeysResponse = callProtectionAPI('GET', '/api/api_keys');
                        if ($apiKeysResponse && isset($apiKeysResponse['api_keys'])) {
                            $api_keys = $apiKeysResponse['api_keys'];
                            
                            // If we deleted the current API key, set a new one
                            if ($key_to_delete === $apiKey && !empty($api_keys)) {
                                $apiKey = $api_keys[0]['api_key'];
                                $_SESSION['api_key'] = $apiKey;
                            } else if (empty($api_keys)) {
                                $apiKey = null;
                                unset($_SESSION['api_key']);
                            }
                        }
                    } else {
                        $_SESSION['error'] = "Failed to delete API key: " . ($response['message'] ?? 'Unknown error');
                    }
                }
                break;
                
            case 'delete_domain':
                if (!canUserAccessFeature($user_plan, 'protection')) {
                    $_SESSION['error'] = "Your plan doesn't include domain protection";
                    break;
                }
                
                $domainId = $_POST['domain_id'] ?? '';
                
                if ($domainId) {
                    // SECURITY FIX: Verify domain ownership before deletion
                    $domainOwned = false;
                    foreach ($domains as $domain) {
                        if ($domain['id'] == $domainId) {
                            $domainOwned = true;
                            break;
                        }
                    }
                    
                    if (!$domainOwned) {
                        $_SESSION['error'] = "You don't have permission to delete this domain";
                        break;
                    }
                    
                    $response = callProtectionAPI('DELETE', '/api/delete_domain/' . $domainId);
                    
                    if ($response && $response['success']) {
                        $_SESSION['success'] = "Domain deleted successfully";
                        // Refresh domains list
                        $domainsResponse = callProtectionAPI('GET', '/api/domains?user_id=' . $user_id);
                        if ($domainsResponse && isset($domainsResponse['domains'])) {
                            $domains = $domainsResponse['domains'];
                        }
                    } else {
                        $_SESSION['error'] = "Failed to delete domain: " . ($response['message'] ?? 'Unknown error');
                    }
                }
                break;
        }
        
        // Refresh page to show updated data
        header("Location: dashboard.php?tab=$activeTab");
        exit();
        
    } catch (Exception $e) {
        $_SESSION['error'] = "API Error: " . $e->getMessage();
    }
}

// Generate random attack data for demo
$attackData = [];
$countries = ['US', 'CN', 'RU', 'BR', 'IN', 'DE', 'GB', 'FR', 'JP', 'KR', 'VN', 'NG', 'TR', 'IR', 'SA'];
$attackTypes = ['DDoS', 'Brute Force', 'SQL Injection', 'XSS', 'Port Scan', 'Malware', 'Phishing'];

for ($i = 0; $i < 50; $i++) {
    $attackData[] = [
        'ip' => rand(1, 255) . '.' . rand(1, 255) . '.' . rand(1, 255) . '.' . rand(1, 255),
        'country' => $countries[array_rand($countries)],
        'type' => $attackTypes[array_rand($attackTypes)],
        'timestamp' => time() - rand(0, 86400),
        'severity' => rand(1, 10),
        'domain' => count($domains) > 0 ? $domains[array_rand($domains)]['name'] : 'example.com'
    ];
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - FireShield</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
    <script src="https://cdn.jsdelivr.net/npm/three"></script>
    <script src="https://cdn.jsdelivr.net/npm/globe.gl"></script>
    <style>
        :root {
            --primary-color: #2c3e50;
            --secondary-color: #3498db;
            --accent-color: #e74c3c;
            --success-color: #27ae60;
            --warning-color: #f39c12;
            --light-bg: #f8f9fa;
            --dark-bg: #2c3e50;
            --card-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            --transition: all 0.3s ease;
        }
        
        body {
            background-color: var(--light-bg);
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            color: #333;
        }
        
        .header {
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            color: white;
            padding: 15px 20px;
            box-shadow: var(--card-shadow);
        }
        
        .stat-card {
            background: white;
            border-radius: 12px;
            padding: 20px;
            box-shadow: var(--card-shadow);
            text-align: center;
            transition: var(--transition);
            height: 100%;
            border: none;
            position: relative;
            overflow: hidden;
        }
        
        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 4px;
            height: 100%;
            background: linear-gradient(to bottom, var(--secondary-color), var(--primary-color));
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0,0,0,0.15);
        }
        
        .stat-number {
            font-size: 2.2rem;
            font-weight: bold;
            color: var(--primary-color);
            margin: 10px 0;
        }
        
        .stat-icon {
            font-size: 1.8rem;
            color: var(--secondary-color);
            margin-bottom: 10px;
        }
        
        .table-container {
            background: white;
            border-radius: 12px;
            padding: 20px;
            box-shadow: var(--card-shadow);
            margin-bottom: 20px;
        }
        
        .admin-card {
            background: white;
            border-radius: 12px;
            padding: 20px;
            box-shadow: var(--card-shadow);
            margin-bottom: 20px;
            height: 100%;
            border: none;
        }
        
        .badge-plan {
            font-size: 0.8rem;
            padding: 5px 10px;
            border-radius: 20px;
        }
        
        .bg-none { background-color: #95a5a6; }
        .bg-basic { background-color: var(--secondary-color); }
        .bg-professional { background-color: var(--primary-color); }
        .bg-enterprise { background-color: #9b59b6; }
        
        .api-status {
            padding: 5px 10px;
            border-radius: 20px;
            font-size: 0.8rem;
        }
        
        .status-online {
            background-color: #d4edda;
            color: #155724;
        }
        
                .status-offline {
            background-color: #f8d7da;
            color: #721c24;
        }
        
        .nav-tabs {
            border-bottom: 2px solid #e9ecef;
        }
        
        .nav-tabs .nav-link {
            color: #6c757d;
            font-weight: 500;
            padding: 12px 20px;
            border: none;
            border-bottom: 3px solid transparent;
            transition: var(--transition);
        }
        
        .nav-tabs .nav-link.active {
            color: var(--primary-color);
            background: transparent;
            border: none;
            border-bottom: 3px solid var(--secondary-color);
        }
        
        .nav-tabs .nav-link:hover {
            border-color: transparent;
            color: var(--primary-color);
        }
        
        .tab-icon {
            margin-right: 8px;
            font-size: 1.1rem;
        }
        
        .btn-primary {
            background-color: var(--secondary-color);
            border-color: var(--secondary-color);
        }
        
        .btn-primary:hover {
            background-color: var(--primary-color);
            border-color: var(--primary-color);
        }
        
        .btn-outline-primary {
            color: var(--secondary-color);
            border-color: var(--secondary-color);
        }
        
        .btn-outline-primary:hover {
            background-color: var(--secondary-color);
            border-color: var(--secondary-color);
            color: white;
        }
        
        .btn-danger {
            background-color: var(--accent-color);
            border-color: var(--accent-color);
        }
        
        #attackGlobe {
            width: 100%;
            height: 500px;
            background: #000;
            border-radius: 12px;
            overflow: hidden;
        }
        
        .globe-controls {
            position: absolute;
            top: 15px;
            right: 15px;
            z-index: 100;
            background: rgba(255, 255, 255, 0.9);
            padding: 10px;
            border-radius: 5px;
            box-shadow: var(--card-shadow);
        }
        
        .attack-info {
            position: absolute;
            bottom: 15px;
            left: 15px;
            z-index: 100;
            background: rgba(0, 0, 0, 0.8);
            color: white;
            padding: 15px;
            border-radius: 5px;
            max-width: 300px;
            display: none;
        }
        
        .time-filter {
            background: rgba(255, 255, 255, 0.9);
            padding: 10px 15px;
            border-radius: 5px;
            margin-bottom: 15px;
            display: inline-block;
        }
        
        .globe-container {
            position: relative;
        }
        
        .domain-selector {
            background: rgba(255, 255, 255, 0.9);
            padding: 10px 15px;
            border-radius: 5px;
            margin-bottom: 15px;
            display: inline-block;
            margin-right: 10px;
        }
        
        .notification-toast {
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 9999;
            min-width: 300px;
        }
        
        .card {
            border: none;
            border-radius: 12px;
            box-shadow: var(--card-shadow);
            transition: var(--transition);
        }
        
                .card:hover {
            box-shadow: 0 8px 15px rgba(0,0,0,0.1);
        }
        
        .form-control, .form-select {
            border-radius: 8px;
            border: 1px solid #ddd;
            padding: 10px 15px;
        }
        
        .form-control:focus, .form-select:focus {
            border-color: var(--secondary-color);
            box-shadow: 0 0 0 0.2rem rgba(52, 152, 219, 0.25);
        }
        
        .progress {
            height: 8px;
            border-radius: 4px;
        }
        
        .modal-content {
            border-radius: 12px;
            border: none;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        
        .modal-header {
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            color: white;
            border-radius: 12px 12px 0 0;
        }
        
        .btn-close {
            filter: invert(1);
        }
    </style>
</head>
<body>
    <!-- Header -->
    <div class="header d-flex justify-content-between align-items-center">
        <div>
            <h2><i class="bi bi-shield-check"></i> FireShield Client Dashboard</h2>
        </div>
        <div class="d-flex align-items-center gap-3">
            <span class="api-status <?php echo $apiOnline ? 'status-online' : 'status-offline'; ?>">
                <?php echo $apiOnline ? 'API Online' : 'API Offline'; ?>
            </span>
            <button class="btn btn-sm btn-outline-light" onclick="window.location.reload()">
                <i class="bi bi-arrow-clockwise me-1"></i> Refresh
            </button>
            <span class="text-light">Welcome, <?php echo htmlspecialchars($user_name); ?></span>
            <a class="btn btn-sm btn-outline-light" href="logout.php"><i class="bi bi-box-arrow-right me-1"></i> Logout</a>
        </div>
    </div>

    <!-- Notification Toast -->
    <div class="notification-toast">
        <?php if (isset($_SESSION['success'])): ?>
            <div class="toast show align-items-center text-white bg-success border-0" role="alert">
                <div class="d-flex">
                    <div class="toast-body">
                        <i class="bi bi-check-circle me-2"></i> <?php echo $_SESSION['success']; ?>
                    </div>
                    <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
                </div>
            </div>
            <?php unset($_SESSION['success']); ?>
        <?php endif; ?>
        
        <?php if (isset($_SESSION['error'])): ?>
            <div class="toast show align-items-center text-white bg-danger border-0" role="alert">
                <div class="d-flex">
                    <div class="toast-body">
                        <i class="bi bi-exclamation-triangle me-2"></i> <?php echo $_SESSION['error']; ?>
                    </div>
                    <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
                </div>
            </div>
            <?php unset($_SESSION['error']); ?>
        <?php endif; ?>
        
        <?php if ($error): ?>
            <div class="toast show align-items-center text-white bg-warning border-0" role="alert">
                <div class="d-flex">
                    <div class="toast-body">
                        <i class="bi bi-info-circle me-2"></i> <?php echo $error; ?>
                    </div>
                    <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
                </div>
            </div>
        <?php endif; ?>
    </div>

    <!-- Main Content -->
    <div class="container-fluid p-4">
        <!-- Tabs Navigation -->
        <ul class="nav nav-tabs mb-4" id="dashboardTabs" role="tablist">
            <li class="nav-item" role="presentation">
                <button class="nav-link <?php echo $activeTab === 'dashboard' ? 'active' : ''; ?>" id="overview-tab" data-bs-toggle="tab" data-bs-target="#overview" type="button" role="tab">
                    <i class="bi bi-house-door tab-icon"></i>Overview
                </button>
            </li>
            <?php if (canUserAccessFeature($user_plan, 'protection')): ?>
            <li class="nav-item" role="presentation">
                <button class="nav-link <?php echo $activeTab === 'protection' ? 'active' : ''; ?>" id="protection-tab" data-bs-toggle="tab" data-bs-target="#protection" type="button" role="tab">
                    <i class="bi bi-shield-check tab-icon"></i>Protection
                </button>
            </li>
            <?php endif; ?>
            <?php if (canUserAccessFeature($user_plan, 'basic_analytics') || canUserAccessFeature($user_plan, 'advanced_analytics')): ?>
                            <button class="nav-link <?php echo $activeTab === 'activity' ? 'active' : ''; ?>" id="activity-tab" data-bs-toggle="tab" data-bs-target="#activity" type="button" role="tab">
                    <i class="bi bi-graph-up tab-icon"></i>Activity
                </button>
            </li>
            <?php endif; ?>
            <li class="nav-item" role="presentation">
                <button class="nav-link <?php echo $activeTab === 'map' ? 'active' : ''; ?>" id="map-tab" data-bs-toggle="tab" data-bs-target="#map" type="button" role="tab">
                    <i class="bi bi-globe tab-icon"></i>Attack Map
                </button>
            </li>
            <?php if (canUserAccessFeature($user_plan, 'api_access')): ?>
            <li class="nav-item" role="presentation">
                <button class="nav-link <?php echo $activeTab === 'settings' ? 'active' : ''; ?>" id="settings-tab" data-bs-toggle="tab" data-bs-target="#settings" type="button" role="tab">
                    <i class="bi bi-gear tab-icon"></i>Settings
                </button>
            </li>
            <?php endif; ?>
        </ul>

        <!-- Tab Content -->
        <div class="tab-content" id="dashboardTabsContent">
            <!-- Overview Tab -->
            <div class="tab-pane fade <?php echo $activeTab === 'dashboard' ? 'show active' : ''; ?>" id="overview" role="tabpanel">
                <!-- Stats Overview -->
                <div class="row mb-4">
                    <div class="col-md-3 mb-3">
                        <div class="stat-card">
                            <div class="stat-icon"><i class="bi bi-globe"></i></div>
                            <div class="stat-number"><?php echo number_format($stats['total_requests']); ?></div>
                            <div class="stat-text">Total Requests</div>
                        </div>
                    </div>
                                        <div class="col-md-3 mb-3">
                        <div class="stat-card">
                            <div class="stat-icon"><i class="bi bi-shield-slash"></i></div>
                            <div class="stat-number"><?php echo number_format($stats['blocked_requests']); ?></div>
                            <div class="stat-text">Blocked Attacks</div>
                        </div>
                    </div>
                    <div class="col-md-3 mb-3">
                        <div class="stat-card">
                            <div class="stat-icon"><i class="bi bi-ban"></i></div>
                            <div class="stat-number"><?php echo number_format($stats['banned_ips']); ?></div>
                            <div class="stat-text">Banned IPs</div>
                        </div>
                    </div>
                    <div class="col-md-3 mb-3">
                        <div class="stat-card">
                            <div class="stat-icon"><i class="bi bi-activity"></i></div>
                            <div class="stat-number"><?php echo number_format($stats['active_sessions']); ?></div>
                            <div class="stat-text">Active Sessions</div>
                        </div>
                    </div>
                </div>

                <!-- Quick Actions -->
                <div class="row mb-4">
                    <div class="col-12">
                        <div class="admin-card">
                            <h4 class="mb-3"><i class="bi bi-lightning"></i> Quick Actions</h4>
                            <div class="row">
                                <?php if (canUserAccessFeature($user_plan, 'protection')): ?>
                                <div class="col-md-3 mb-3 text-center">
                                    <button class="btn btn-outline-primary w-100" data-bs-toggle="modal" data-bs-target="#banIpModal">
                                        <i class="bi bi-shield-slash me-2"></i> Ban IP
                                    </button>
                                </div>
                                <div class="col-md-3 mb-3 text-center">
                                    <button class="btn btn-outline-primary w-100" data-bs-toggle="modal" data-bs-target="#allowIpModal">
                                        <i class="bi bi-shield-check me-2"></i> Allow IP
                                    </button>
                                </div>
                                <div class="col-md-3 mb-3 text-center">
                                    <button class="btn btn-outline-primary w-100" data-bs-toggle="modal" data-bs-target="#addDomainModal">
                                        <i class="bi bi-plus-circle me-2"></i> Add Domain
                                    </button>
                                </div>
                                <?php endif; ?>
                                <div class="col-md-3 mb-3 text-center">
                                    <a href="services.php" class="btn btn-primary w-100">
                                        <i class="bi bi-arrow-up-circle me-2"></i> Upgrade Plan
                                    </a>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Plan Info -->
                <div class="admin-card">
                    <h4 class="mb-3"><i class="bi bi-award"></i> Your Plan: <?php echo ucfirst($user_plan); ?></h4>
                    <div class="row">
                        <div class="col-md-6">
                            <div class="bg-light p-3 rounded">
                                <h6>Domain Limit</h6>
                                <p class="mb-0">
                                    <?php if ($maxDomains === -1): ?>
                                        Unlimited domains
                                    <?php else: ?>
                                        <?php echo count($domains); ?> / <?php echo $maxDomains; ?> domains used
                                    <?php endif; ?>
                                </p>
                                <div class="progress mt-2" style="height: 8px;">
                                    <?php 
                                    $usagePercent = $maxDomains === -1 ? 0 : min(100, (count($domains) / $maxDomains) * 100);
                                    $progressClass = $usagePercent >= 90 ? 'bg-danger' : ($usagePercent >= 70 ? 'bg-warning' : 'bg-success');
                                    ?>
                                    <div class="progress-bar <?php echo $progressClass; ?>" role="progressbar" 
                                         style="width: <?php echo $usagePercent; ?>%" 
                                         aria-valuenow="<?php echo $usagePercent; ?>" 
                                         aria-valuemin="0" 
                                         aria-valuemax="100"></div>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="bg-light p-3 rounded">
                                <h6>Features</h6>
                                <ul class="list-unstyled mb-0">
                                    <?php foreach ($planLimits['features'] as $feature): ?>
                                        <li><i class="bi bi-check-circle text-success me-2"></i> 
                                            <?php echo ucfirst(str_replace('_', ' ', $feature)); ?>
                                        </li>
                                    <?php endforeach; ?>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Protection Tab -->
            <?php if (canUserAccessFeature($user_plan, 'protection')): ?>
            <div class="tab-pane fade <?php echo $activeTab === 'protection' ? 'show active' : ''; ?>" id="protection" role="tabpanel">
                <div class="admin-card">
                    <h4 class="mb-3"><i class="bi bi-shield-check"></i> Domain Protection</h4>

                    <?php if (empty($domains)): ?>
                        <div class="text-center py-5">
                            <i class="bi bi-globe display-4 text-muted"></i>
                            <h5 class="text-muted mt-3">No domains protected yet</h5>
                            <p class="text-muted">Add your first domain to start protection</p>
                            <button class="btn btn-primary mt-2" data-bs-toggle="modal" data-bs-target="#addDomainModal">
                                <i class="bi bi-plus-circle me-2"></i> Add Domain
                            </button>
                        </div>
                    <?php else: ?>
                        <div class="row">
                            <?php foreach ($domains as $domain): ?>
                                <div class="col-md-6 mb-3">
                                    <div class="card">
                                        <div class="card-body">
                                            <div class="d-flex justify-content-between align-items-center mb-2">
                                                <h5 class="card-title mb-0"><?php echo htmlspecialchars($domain['name']); ?></h5>
                                                <span class="badge bg-<?php echo $domain['status'] === 'active' ? 'success' : 'secondary'; ?>">
                                                    <?php echo ucfirst($domain['status']); ?>
                                                </span>
                                            </div>
                                            <p class="text-muted mb-2">Target: <?php echo htmlspecialchars($domain['target_website']); ?></p>
                                            <p class="text-muted mb-3">Added: <?php echo date('M j, Y', (int)$domain['created_at']); ?></p>
                                            <div class="d-flex justify-content-between align-items-center">
                                                <span>DDoS Protection:</span>
                                                <div class="form-check form-switch">
                                                    <input class="form-check-input" type="checkbox" <?php echo $domain['protection_enabled'] ? 'checked' : ''; ?> 
                                                           onchange="toggleProtection(<?php echo $domain['id']; ?>, this.checked)">
                                                </div>
                                            </div>
                                            <div class="mt-3">
                                                <form method="POST" class="d-inline">
                                                    <input type="hidden" name="action" value="delete_domain">
                                                    <input type="hidden" name="domain_id" value="<?php echo $domain['id']; ?>">
                                                    <button type="submit" class="btn btn-sm btn-outline-danger" onclick="return confirm('Are you sure you want to delete this domain?')">
                                                        <i class="bi bi-trash me-1"></i> Delete
                                                    </button>
                                                </form>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>

                    <?php if ($maxDomains === -1 || count($domains) < $maxDomains): ?>
                        <div class="text-center mt-4">
                            <button class="btn btn-outline-primary" data-bs-toggle="modal" data-bs-target="#addDomainModal">
                                <i class="bi bi-plus-circle me-2"></i> Add Another Domain
                            </button>
                        </div>
                    <?php else: ?>
                        <div class="alert alert-info mt-3">
                            <i class="bi bi-info-circle me-2"></i>
                            You've reached the maximum limit of <?php echo $maxDomains; ?> domains for your plan.
                        </div>
                    <?php endif; ?>
                </div>
            </div>
            <?php endif; ?>

            <!-- Activity Tab -->
            <?php if (canUserAccessFeature($user_plan, 'basic_analytics') || canUserAccessFeature($user_plan, 'advanced_analytics')): ?>
            <div class="tab-pane fade <?php echo $activeTab === 'activity' ? 'show active' : ''; ?>" id="activity" role="tabpanel">
                <div class="admin-card">
                    <h4 class="mb-3"><i class="bi bi-clock-history"></i> Recent Activity</h4>
                    
                    <?php if (empty($activities)): ?>
                        <div class="text-center py-5">
                            <i class="bi bi-inbox display-4 text-muted"></i>
                            <p class="text-muted mt-3">No recent activity detected</p>
                        </div>
                    <?php else: ?>
                        <div class="table-responsive">
                            <table class="table table-hover">
                                <thead>
                                    <tr>
                                        <th>Time</th>
                                        <th>IP Address</th>
                                        <th>Action</th>
                                        <th>Details</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($activities as $activity): ?>
                                        <tr>
                                            <td><?php echo date('M j, H:i:s', (int)$activity['timestamp']); ?></td>
                                            <td><?php echo htmlspecialchars($activity['ip']); ?></td>
                                            <td><span class="badge bg-danger">Blocked</span></td>
                                            <td><?php echo htmlspecialchars($activity['method'] . ' ' . $activity['path']); ?></td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
            <?php endif; ?>

            <!-- Attack Map Tab -->
            <div class="tab-pane fade <?php echo $activeTab === 'map' ? 'show active' : ''; ?>" id="map" role="tabpanel">
                <div class="admin-card">
                    <div class="d-flex justify-content-between align-items-center mb-4">
                        <h4><i class="bi bi-globe"></i> Live Attack Map</h4>
                        <div>
                            <?php if (count($domains) > 0): ?>
                            <div class="domain-selector">
                                <span class="me-2">Domain:</span>
                                <select class="form-select form-select-sm" id="domainFilter">
                                    <option value="all">All Domains</option>
                                    <?php foreach ($domains as $domain): ?>
                                        <option value="<?php echo htmlspecialchars($domain['name']); ?>"><?php echo htmlspecialchars($domain['name']); ?></option>
                                    <?php endforeach; ?>
                                </select>
                            </div>
                            <?php endif; ?>
                            <div class="time-filter">
                                <span class="me-2">Time Range:</span>
                                <div class="btn-group btn-group-sm">
                                                                        <button type="button" class="btn btn-outline-primary active">Live</button>
                                    <button type="button" class="btn btn-outline-primary">1H</button>
                                    <button type="button" class="btn btn-outline-primary">24H</button>
                                    <button type="button" class="btn btn-outline-primary">7D</button>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="globe-container">
                        <div id="attackGlobe"></div>
                        <div class="globe-controls">
                            <div class="form-check form-switch">
                                <input class="form-check-input" type="checkbox" id="autoRotate" checked>
                                <label class="form-check-label" for="autoRotate">Auto Rotate</label>
                            </div>
                            <div class="form-check form-switch mt-2">
                                <input class="form-check-input" type="checkbox" id="showArcs" checked>
                                <label class="form-check-label" for="showArcs">Show Attack Paths</label>
                            </div>
                        </div>
                        <div class="attack-info" id="attackInfo">
                            <h6>Attack Details</h6>
                            <div><strong>IP:</strong> <span id="info-ip"></span></div>
                            <div><strong>Country:</strong> <span id="info-country"></span></div>
                            <div><strong>Type:</strong> <span id="info-type"></span></div>
                            <div><strong>Severity:</strong> <span id="info-severity"></span></div>
                            <div><strong>Domain:</strong> <span id="info-domain"></span></div>
                            <div><strong>Time:</strong> <span id="info-time"></span></div>
                        </div>
                    </div>
                    
                    <div class="row mt-4">
                        <div class="col-md-6">
                            <h5><i class="bi bi-graph-up"></i> Attack Statistics</h5>
                            <div class="table-responsive">
                                <table class="table table-sm">
                                    <thead>
                                        <tr>
                                            <th>Attack Type</th>
                                            <th>Count</th>
                                            <th>Trend</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <tr>
                                            <td>DDoS</td>
                                            <td>142</td>
                                            <td><span class="text-danger"><i class="bi bi-arrow-up"></i> 12%</span></td>
                                        </tr>
                                        <tr>
                                            <td>Brute Force</td>
                                            <td>89</td>
                                                                                        <td><span class="text-success"><i class="bi bi-arrow-down"></i> 5%</span></td>
                                        </tr>
                                        <tr>
                                            <td>SQL Injection</td>
                                            <td>34</td>
                                            <td><span class="text-danger"><i class="bi bi-arrow-up"></i> 8%</span></td>
                                        </tr>
                                        <tr>
                                            <td>XSS</td>
                                            <td>27</td>
                                            <td><span class="text-success"><i class="bi bi-arrow-down"></i> 3%</span></td>
                                        </tr>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <h5><i class="bi bi-flag"></i> Top Source Countries</h5>
                            <div class="table-responsive">
                                <table class="table table-sm">
                                    <thead>
                                        <tr>
                                            <th>Country</th>
                                            <th>Attacks</th>
                                            <th>Percentage</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <tr>
                                            <td><i class="bi bi-flag-fill text-danger"></i> China</td>
                                            <td>87</td>
                                            <td>29.8%</td>
                                        </tr>
                                        <tr>
                                            <td><i class="bi bi-flag-fill text-primary"></i> United States</td>
                                            <td>63</td>
                                            <td>21.6%</td>
                                        </tr>
                                        <tr>
                                                                                    <td><i class="bi bi-flag-fill text-warning"></i> Russia</td>
                                            <td>42</td>
                                            <td>14.4%</td>
                                        </tr>
                                        <tr>
                                            <td><i class="bi bi-flag-fill text-success"></i> Brazil</td>
                                            <td>31</td>
                                            <td>10.6%</td>
                                        </tr>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Settings Tab -->
            <?php if (canUserAccessFeature($user_plan, 'api_access')): ?>
            <div class="tab-pane fade <?php echo $activeTab === 'settings' ? 'show active' : ''; ?>" id="settings" role="tabpanel">
                <div class="row">
                    <div class="col-lg-6 mb-4">
                        <div class="admin-card">
                            <h4 class="mb-3"><i class="bi bi-key"></i> API Configuration</h4>
                            
                            <div class="mb-4">
                                <label class="form-label">Your API Key</label>
                                <div class="input-group">
                                    <input type="password" class="form-control api-key-mask" value="<?php echo $apiKey ?: 'No API key generated'; ?>" readonly>
                                    <button class="btn btn-outline-secondary" type="button" id="toggleApiKey">
                                        <i class="bi bi-eye"></i>
                                    </button>
                                </div>
                                <small class="text-muted">Click the eye icon to reveal/hide</small>
                            </div>
                            
                            <form method="POST">
                                <input type="hidden" name="action" value="generate_api_key">
                                <div class="mb-3">
                                    <label class="form-label">Note (optional)</label>
                                    <input type="text" class="form-control" name="note" placeholder="Description for this API key">
                                </div>
                                <button type="submit" class="btn btn-primary w-100">
                                    <i class="bi bi-arrow-repeat me-2"></i> Generate New API Key
                                </button>
                            </form>
                            
                            <?php if (!empty($api_keys)): ?>
                            <div class="mt-4">
                                <h5>Your API Keys</h5>
                                <div class="table-responsive">
                                    <table class="table table-sm">
                                        <thead>
                                            <tr>
                                                <th>Key</th>
                                                <th>Note</th>
                                                <th>Created</th>
                                                <th>Action</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php foreach ($api_keys as $key): ?>
                                            <tr>
                                                <td><?php echo substr($key['api_key'], 0, 8) . '...'; ?></td>
                                                <td><?php echo htmlspecialchars($key['note']); ?></td>
                                                <td><?php echo date('M j, Y', (int)$key['created_at']); ?></td>
                                                <td>
                                                    <form method="POST" class="d-inline">
                                                        <input type="hidden" name="action" value="delete_api_key">
                                                        <input type="hidden" name="api_key" value="<?php echo $key['api_key']; ?>">
                                                        <button type="submit" class="btn btn-sm btn-outline-danger" onclick="return confirm('Are you sure you want to delete this API key?')">
                                                            <i class="bi bi-trash"></i>
                                                        </button>
                                                    </form>
                                                </td>
                                            </tr>
                                            <?php endforeach; ?>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                            <?php endif; ?>
                                                </div>
                    </div>
                    
                    <div class="col-lg-6 mb-4">
                        <div class="admin-card">
                            <h4 class="mb-3"><i class="bi bi-person"></i> Account Information</h4>
                            
                            <div class="mb-3">
                                <label class="form-label">Name</label>
                                <input type="text" class="form-control" value="<?php echo htmlspecialchars($user_name); ?>" readonly>
                            </div>
                            
                            <div class="mb-3">
                                <label class="form-label">Email</label>
                                <input type="email" class="form-control" value="<?php echo htmlspecialchars($user_email); ?>" readonly>
                            </div>
                            
                            <div class="mb-3">
                                <label class="form-label">Plan</label>
                                <input type="text" class="form-control" value="<?php echo ucfirst($user_plan); ?>" readonly>
                            </div>
                            
                            <div class="text-center">
                                <a href="services.php" class="btn btn-outline-primary">
                                    <i class="bi bi-arrow-up-circle me-2"></i> Upgrade Plan
                                </a>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <?php endif; ?>
        </div>
    </div>

    <!-- Modals -->
    <?php if ($user_plan !== 'none' && canUserAccessFeature($user_plan, 'protection')): ?>
    <!-- Ban IP Modal -->
    <div class="modal fade" id="banIpModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Ban IP Address</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <form method="POST">
                    <input type="hidden" name="action" value="ban_ip">
                    <div class="modal-body">
                        <div class="mb-3">
                            <label class="form-label">IP Address</label>
                            <input type="text" class="form-control" name="ip" placeholder="192.168.1.1" required
                                   pattern="^([0-9]{1,3}\.){3}[0-9]{1,3}$">
                            <div class="form-text">Enter a valid IPv4 address</div>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Reason</label>
                            <textarea class="form-control" name="reason" rows="3" placeholder="Reason for banning this IP" required></textarea>
                        </div>
                                        </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-danger">Ban IP</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- Allow IP Modal -->
    <div class="modal fade" id="allowIpModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Allow IP Address</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <form method="POST">
                    <input type="hidden" name="action" value="allow_ip">
                    <div class="modal-body">
                        <div class="mb-3">
                            <label class="form-label">IP Address</label>
                            <input type="text" class="form-control" name="ip" placeholder="192.168.1.1" required
                                   pattern="^([0-9]{1,3}\.){3}[0-9]{1,3}$">
                                                        <div class="form-text">Enter a valid IPv4 address</div>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Note (Optional)</label>
                            <textarea class="form-control" name="note" rows="2" placeholder="Note about this IP"></textarea>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                                                    <button type="submit" class="btn btn-success">Add to Allowlist</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- Add Domain Modal -->
    <div class="modal fade" id="addDomainModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Add Domain</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <form method="POST">
                    <input type="hidden" name="action" value="add_domain">
                    <div class="modal-body">
                        <div class="mb-3">
                            <label class="form-label">Domain Name</label>
                            <input type="text" class="form-control" name="domain" placeholder="example.com" required>
                            <div class="form-text">
                                Enter the domain you want to protect (e.g., example.com)
                            </div>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Target Website</label>
                            <input type="url" class="form-control" name="target_website" placeholder="https://origin-website.com" required>
                            <div class="form-text">
                                Enter the origin website URL that will be protected (e.g., https://your-website.com)
                            </div>
                        </div>
                        <div class="form-text">
                            <?php if ($maxDomains === -1): ?>
                                You have unlimited domains
                            <?php else: ?>
                                You have <?php echo $maxDomains - count($domains); ?> domains remaining in your plan
                            <?php endif; ?>
                        </div>
                    </div>
                    <div class="modal-footer">
                                                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary">Add Domain</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    <?php endif; ?>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Toggle protection for a domain
        function toggleProtection(domainId, enabled) {
            const formData = new FormData();
            formData.append('action', 'toggle_protection');
            formData.append('domain_id', domainId);
            formData.append('enabled', enabled);
            
            fetch('', {
                method: 'POST',
                body: formData
            }).then(response => {
                if (response.ok) {
                    window.location.reload();
                }
            });
        }

        // Toggle API key visibility
        document.getElementById('toggleApiKey').addEventListener('click', function() {
            const apiKeyField = document.querySelector('.api-key-mask');
            if (apiKeyField.type === 'password') {
                apiKeyField.type = 'text';
                this.innerHTML = '<i class="bi bi-eye-slash"></i>';
            } else {
                apiKeyField.type = 'password';
                this.innerHTML = '<i class="bi bi-eye"></i>';
            }
        });

        // Initialize attack globe
        function initAttackGlobe() {
            // Sample attack data (in real app, this would come from your backend)
            const attacks = <?php echo json_encode($attackData); ?>;
            const selectedDomain = document.getElementById('domainFilter')?.value || 'all';
            
            // Filter attacks by selected domain
            const filteredAttacks = selectedDomain === 'all' 
                ? attacks 
                : attacks.filter(attack => attack.domain === selectedDomain);
            
            // Get country coordinates (in real app, you'd have a proper mapping)
            const countryCoords = {
                'US': { lat: 37.0902, lng: -95.7129 },
                'CN': { lat: 35.8617, lng: 104.1954 },
                'RU': { lat: 61.5240, lng: 105.3188 },
                'BR': { lat: -14.2350, lng: -51.9253 },
                'IN': { lat: 20.5937, lng: 78.9629 },
                'DE': { lat: 51.1657, lng: 10.4515 },
                'GB': { lat: 55.3781, lng: -3.4360 },
                'FR': { lat: 46.6034, lng: 1.8883 },
                'JP': { lat: 36.2048, lng: 138.2529 },
                'KR': { lat: 35.9078, lng: 127.7669 },
                'VN': { lat: 14.0583, lng: 108.2772 },
                'NG': { lat: 9.0820, lng: 8.6753 },
                'TR': { lat: 38.9637, lng: 35.2433 },
                'IR': { lat: 32.4279, lng: 53.6880 },
                'SA': { lat: 23.8859, lng: 45.0792 }
            };
            
            // Create globe
            const globe = Globe()
                .globeImageUrl('//unpkg.com/three-globe/example/img/earth-blue-marble.jpg')
                .bumpImageUrl('//unpkg.com/three-globe/example/img/earth-topology.png')
                .backgroundImageUrl('//unpkg.com/three-globe/example/img/night-sky.png')
                (document.getElementById('attackGlobe'));
            
            // Add attack points
            const attackPoints = filteredAttacks.map(attack => {
                const coords = countryCoords[attack.country] || { lat: 0, lng: 0 };
                return {
                    lat: coords.lat + (Math.random() - 0.5) * 10,
                    lng: coords.lng + (Math.random() - 0.5) * 10,
                    size: attack.severity / 3,
                    color: attack.severity > 7 ? 'red' : attack.severity > 4 ? 'orange' : 'yellow',
                    attack: attack
                };
            });
            
            globe.pointsData(attackPoints)
                .pointAltitude(0.001)
                .pointRadius('size')
                .pointColor('color')
                .pointLabel(point => `
                    <div>IP: ${point.attack.ip}</div>
                    <div>Country: ${point.attack.country}</div>
                    <div>Type: ${point.attack.type}</div>
                    <div>Severity: ${point.attack.severity}/10</div>
                    <div>Domain: ${point.attack.domain}</div>
                `);
            
            // Add attack arcs (lines showing attack paths)
            const attackArcs = filteredAttacks.map(attack => {
                const coords = countryCoords[attack.country] || { lat: 0, lng: 0 };
                return {
                    startLat: coords.lat + (Math.random() - 0.5) * 15,
                    startLng: coords.lng + (Math.random() - 0.5) * 15,
                    endLat: 39.8283, // Your server location (example)
                    endLng: -98.5795,
                                        color: attack.severity > 7 ? ['red', 'orange'] : attack.severity > 4 ? ['orange', 'yellow'] : ['yellow', 'white']
                };
            });
            
            globe.arcsData(attackArcs)
                .arcColor('color')
                .arcDashLength(0.5)
                .arcDashGap(1)
                .arcDashAnimateTime(1000 + Math.random() * 1000);
            
            // Auto-rotate
            globe.controls().autoRotate = true;
            globe.controls().autoRotateSpeed = 0.5;
            
            // Toggle auto-rotate
            document.getElementById('autoRotate').addEventListener('change', function() {
                globe.controls().autoRotate = this.checked;
            });
            
            // Toggle arcs visibility
            document.getElementById('showArcs').addEventListener('change', function() {
                globe.arcsVisibility(this.checked);
            });
            
            // Add click handler to show attack details
            globe.onPointClick(point => {
                const info = document.getElementById('attackInfo');
                document.getElementById('info-ip').textContent = point.attack.ip;
                document.getElementById('info-country').textContent = point.attack.country;
                document.getElementById('info-type').textContent = point.attack.type;
                document.getElementById('info-severity').textContent = point.attack.severity + '/10';
                document.getElementById('info-domain').textContent = point.attack.domain;
                document.getElementById('info-time').textContent = new Date(point.attack.timestamp * 1000).toLocaleString();
                info.style.display = 'block';
            });
            
            // Add random attacks periodically to simulate live data
            setInterval(() => {
                const newAttack = {
                    ip: `${rand(1, 255)}.${rand(1, 255)}.${rand(1, 255)}.${rand(1, 255)}`,
                    country: attacks[rand(0, attacks.length - 1)].country,
                    type: attacks[rand(0, attacks.length - 1)].type,
                    timestamp: Date.now() / 1000,
                    severity: rand(1, 10),
                    domain: '<?php echo count($domains) > 0 ? $domains[array_rand($domains)]['name'] : 'example.com'; ?>'
                };
                
                const coords = countryCoords[newAttack.country] || { lat: 0, lng: 0 };
                const newPoint = {
                    lat: coords.lat + (Math.random() - 0.5) * 10,
                    lng: coords.lng + (Math.random() - 0.5) * 10,
                    size: newAttack.severity / 3,
                    color: newAttack.severity > 7 ? 'red' : newAttack.severity > 4 ? 'orange' : 'yellow',
                    attack: newAttack
                };
                
                // Add new point
                attackPoints.push(newPoint);
                globe.pointsData([...attackPoints]);
                
                // Add new arc
                const newArc = {
                    startLat: coords.lat + (Math.random() - 0.5) * 15,
                                        startLng: coords.lng + (Math.random() - 0.5) * 15,
                    endLat: 39.8283,
                    endLng: -98.5795,
                    color: newAttack.severity > 7 ? ['red', 'orange'] : newAttack.severity > 4 ? ['orange', 'yellow'] : ['yellow', 'white']
                };
                
                attackArcs.push(newArc);
                globe.arcsData([...attackArcs]);
                
            }, 3000); // Add new attack every 3 seconds
            
            return globe;
        }
        
        // Helper function for random numbers
        function rand(min, max) {
            return Math.floor(Math.random() * (max - min + 1)) + min;
        }
        
        // Initialize the globe when the map tab is shown
        document.getElementById('map-tab').addEventListener('shown.bs.tab', function() {
            window.globe = initAttackGlobe();
        });
        
        // Update globe when domain filter changes
        const domainFilter = document.getElementById('domainFilter');
        if (domainFilter) {
            domainFilter.addEventListener('change', function() {
                if (window.globe) {
                    window.globe = initAttackGlobe();
                }
            });
        }
        
        // Auto-refresh data every 60 seconds instead of 30
        setInterval(function() {
            window.location.reload();
        }, 60000);
        
        // Auto-hide notifications after 5 seconds
        setTimeout(function() {
            document.querySelectorAll('.toast').forEach(toast => {
                toast.classList.remove('show');
            });
        }, 5000);
    </script>
</body>
</html>