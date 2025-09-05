<?php
function isLoggedIn() {
    return isset($_SESSION['user_id']);
}

function isAdmin() {
    return isset($_SESSION['admin_id']);
}

function redirect($url) {
    header("Location: $url");
    exit();
}

function getClientIP() {
    if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
        return $_SERVER['HTTP_CLIENT_IP'];
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        return $_SERVER['HTTP_X_FORWARDED_FOR'];
    } else {
        return $_SERVER['REMOTE_ADDR'];
    }
}

function getUserPlanLimits($plan) {
    $limits = [
        'none' => ['max_domains' => 0, 'features' => []],
        'basic' => ['max_domains' => 5, 'features' => ['protection', 'basic_analytics']],
        'professional' => ['max_domains' => 20, 'features' => ['protection', 'advanced_analytics', 'api_access']],
        'enterprise' => ['max_domains' => -1, 'features' => ['protection', 'advanced_analytics', 'api_access', 'priority_support']]
    ];
    
    return $limits[$plan] ?? $limits['none'];
}

function canUserAccessFeature($userPlan, $feature) {
    $limits = getUserPlanLimits($userPlan);
    return in_array($feature, $limits['features']);
}

function getMaxDomainsForPlan($plan) {
    $limits = getUserPlanLimits($plan);
    return $limits['max_domains'];
}

function isFeatureAvailable($userPlan, $feature) {
    return canUserAccessFeature($userPlan, $feature);
}

/**
 * Check if cURL is available
 */
function isCurlAvailable() {
    return function_exists('curl_init');
}

/**
 * Make HTTP request with timeout - works with or without cURL
 */
function makeHttpRequest($url, $options = []) {
    if (isCurlAvailable()) {
        return makeCurlRequest($url, $options);
    } else {
        return makeStreamRequest($url, $options);
    }
}

/**
 * Make request using cURL
 */
function makeCurlRequest($url, $options = []) {
    $ch = curl_init();
    
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, $options['timeout'] ?? 5);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $options['connect_timeout'] ?? 3);
    
    if (isset($options['headers'])) {
        curl_setopt($ch, CURLOPT_HTTPHEADER, $options['headers']);
    }
    
    if (isset($options['method'])) {
        if ($options['method'] === 'POST') {
            curl_setopt($ch, CURLOPT_POST, true);
        } else {
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $options['method']);
        }
    }
    
    if (isset($options['data'])) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, $options['data']);
    }
    
    if (isset($options['no_body'])) {
        curl_setopt($ch, CURLOPT_NOBODY, true);
    }
    
    $result = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    
    curl_close($ch);
    
    return [
        'result' => $result,
        'http_code' => $http_code,
        'error' => $error,
        'success' => $result !== false
    ];
}

/**
 * Make request using stream context (fallback without cURL)
 */
function makeStreamRequest($url, $options = []) {
    $contextOptions = [
        'http' => [
            'timeout' => $options['timeout'] ?? 5,
            'ignore_errors' => true
        ]
    ];
    
    if (isset($options['headers'])) {
        $contextOptions['http']['header'] = implode("\r\n", $options['headers']);
    }
    
    if (isset($options['method'])) {
        $contextOptions['http']['method'] = $options['method'];
    }
    
    if (isset($options['data'])) {
        $contextOptions['http']['content'] = $options['data'];
    }
    
    $context = stream_context_create($contextOptions);
    
    // Use error suppression to handle timeouts gracefully
    $result = @file_get_contents($url, false, $context);
    
    $http_code = 0;
    if (isset($http_response_header[0])) {
        preg_match('/HTTP\/\d\.\d\s+(\d+)/', $http_response_header[0], $matches);
        $http_code = $matches[1] ?? 0;
    }
    
    $error = null;
    if ($result === false) {
        $error = error_get_last();
        $error = $error['message'] ?? 'Unknown error';
    }
    
    return [
        'result' => $result,
        'http_code' => (int)$http_code,
        'error' => $error,
        'success' => $result !== false
    ];
}

/**
 * Call the protection API with proper authentication and timeout handling
 */
function callProtectionAPI($method, $endpoint, $data = []) {
    $url = 'http://localhost:8080' . $endpoint;
    
    $headers = [
        "Content-type: application/json",
    ];
    
    // Add API key authentication if available
    if (isset($_SESSION['api_key'])) {
        $headers[] = "X-API-Key: " . $_SESSION['api_key'];
    }
    
    $options = [
        'method' => $method,
        'headers' => $headers,
        'timeout' => 5,
        'connect_timeout' => 3
    ];
    
    if (($method === 'POST' || $method === 'PUT') && !empty($data)) {
        $options['data'] = json_encode($data);
    }
    
    $response = makeHttpRequest($url, $options);
    
    // Handle connection errors
    if (!$response['success']) {
        throw new Exception("Failed to connect to protection API: " . ($response['error'] ?: 'Unknown error'));
    }
    
    // Handle HTTP errors
    if ($response['http_code'] >= 400) {
        throw new Exception("API returned HTTP " . $response['http_code']);
    }
    
    $result = json_decode($response['result'], true);
    
    // Check if we got a valid JSON response
    if (json_last_error() !== JSON_ERROR_NONE) {
        throw new Exception("Invalid JSON response from API");
    }
    
    // Check if we got an authentication error
    if (isset($result['detail']) && $result['detail'] === 'Invalid API key') {
        // Clear invalid API key
        unset($_SESSION['api_key']);
        throw new Exception("Invalid API key. Please generate a new one.");
    }
    
    return $result;
}

/**
 * Check if API is online with proper timeout handling
 */
function checkAPIStatus() {
    $url = 'http://localhost:8080/api/health';
    
    $options = [
        'method' => 'GET',
        'timeout' => 3,
        'connect_timeout' => 2,
        'no_body' => true
    ];
    
    $response = makeHttpRequest($url, $options);
    
    return $response['success'] && $response['http_code'] >= 200 && $response['http_code'] < 400;
}

/**
 * Generate API key with timeout handling
 */
function generateUserAPIKey($note = '') {
    $url = 'http://localhost:8080/api/generate_api_key';
    
    $headers = [
        "Content-type: application/json",
    ];
    
    $data = [];
    if (!empty($note)) {
        $data['note'] = $note;
    }
    
    $options = [
        'method' => 'POST',
        'headers' => $headers,
        'timeout' => 5,
        'connect_timeout' => 3
    ];
    
    if (!empty($data)) {
        $options['data'] = json_encode($data);
    }
    
    $response = makeHttpRequest($url, $options);
    
    if (!$response['success']) {
        throw new Exception("Failed to connect to protection API: " . ($response['error'] ?: 'Unknown error'));
    }
    
    if ($response['http_code'] >= 400) {
        throw new Exception("API returned HTTP " . $response['http_code']);
    }
    
    $result = json_decode($response['result'], true);
    
    if (json_last_error() !== JSON_ERROR_NONE) {
        throw new Exception("Invalid JSON response from API");
    }
    
    return $result;
}

/**
 * Ensure API key is available with proper timeout handling
 */
function ensureAPIKey() {
    // Check if we already have an API key in session
    if (!empty($_SESSION['api_key'])) {
        return true;
    }
    
    // Check if we've already tried to generate an API key in this session
    if (isset($_SESSION['api_key_generation_attempted'])) {
        return false; // Don't try again to prevent infinite loop
    }
    
    try {
        // Mark that we've attempted to generate an API key
        $_SESSION['api_key_generation_attempted'] = true;
        
        // Generate a new API key
        $response = generateUserAPIKey('Auto-generated from dashboard');
        if ($response && isset($response['success']) && $response['success']) {
            $_SESSION['api_key'] = $response['api_key'];
            // Clear the attempt flag since we succeeded
            unset($_SESSION['api_key_generation_attempted']);
            return true;
        } else {
            error_log("API key generation failed: " . ($response['message'] ?? 'Unknown error'));
            return false;
        }
    } catch (Exception $e) {
        error_log("API key generation failed: " . $e->getMessage());
        return false;
    }
}

/**
 * Get API keys list with timeout handling
 */
function getAPIKeysList() {
    try {
        return callProtectionAPI('GET', '/api/api_keys');
    } catch (Exception $e) {
        error_log("Failed to get API keys: " . $e->getMessage());
        return ['api_keys' => []];
    }
}

/**
 * Delete API key with timeout handling
 */
function deleteAPIKey($apiKey) {
    try {
        return callProtectionAPI('DELETE', '/api/delete_api_key/' . urlencode($apiKey));
    } catch (Exception $e) {
        error_log("Failed to delete API key: " . $e->getMessage());
        return ['success' => false, 'message' => $e->getMessage()];
    }
}

/**
 * Get domains list with timeout handling
 */
function getDomainsList() {
    try {
        return callProtectionAPI('GET', '/api/domains');
    } catch (Exception $e) {
        error_log("Failed to get domains: " . $e->getMessage());
        return ['domains' => []];
    }
}

/**
 * Add a new domain with timeout handling
 */
function addDomain($domain, $target_website) {
    try {
        return callProtectionAPI('POST', '/api/add_domain', [
            'domain' => $domain,
            'target_website' => $target_website
        ]);
    } catch (Exception $e) {
        error_log("Failed to add domain: " . $e->getMessage());
        return ['success' => false, 'message' => $e->getMessage()];
    }
}

/**
 * Delete a domain with timeout handling
 */
function deleteDomain($domainId) {
    try {
        return callProtectionAPI('DELETE', '/api/delete_domain/' . $domainId);
    } catch (Exception $e) {
        error_log("Failed to delete domain: " . $e->getMessage());
        return ['success' => false, 'message' => $e->getMessage()];
    }
}

/**
 * Toggle domain protection with timeout handling
 */
function toggleDomainProtection($domainId, $enabled) {
    try {
        return callProtectionAPI('POST', '/api/toggle_protection', [
            'domain_id' => $domainId,
            'enabled' => $enabled
        ]);
    } catch (Exception $e) {
        error_log("Failed to toggle protection: " . $e->getMessage());
        return ['success' => false, 'message' => $e->getMessage()];
    }
}

/**
 * Get protection stats with timeout handling
 */
function getProtectionStats() {
    try {
        return callProtectionAPI('GET', '/api/protection/stats');
    } catch (Exception $e) {
        error_log("Failed to get protection stats: " . $e->getMessage());
        return [
            'total_requests' => 0,
            'blocked_requests' => 0,
            'banned_ips' => 0,
            'allowed_ips' => 0,
            'active_sessions' => 0
        ];
    }
}

/**
 * Get protection activity with timeout handling
 */
function getProtectionActivity($limit = 10) {
    try {
        return callProtectionAPI('GET', '/api/protection/activity?limit=' . $limit);
    } catch (Exception $e) {
        error_log("Failed to get protection activity: " . $e->getMessage());
        return ['activities' => []];
    }
}
?>