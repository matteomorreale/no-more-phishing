<?php
/**
 * No More Phishing - Bootstrap
 * @author Matteo Morreale
 * @version 1.0.0
 *
 * Gestisce CORS, sicurezza, rate limiting e utility condivise.
 */

require_once __DIR__ . '/config.php';

// =====================================================================
// Gestione Errori
// =====================================================================

error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);

// =====================================================================
// Headers di sicurezza e CORS
// =====================================================================

function setCorsHeaders(): void
{
    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';

    // Accetta richieste dall'estensione Chrome
    $allowedOrigins = [
        'chrome-extension://' . ALLOWED_EXTENSION_ID,
        // Aggiungi altri browser Chromium se necessario
    ];

    if (in_array($origin, $allowedOrigins, true) || empty($origin)) {
        header('Access-Control-Allow-Origin: ' . ($origin ?: '*'));
    }

    header('Access-Control-Allow-Methods: POST, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, X-NMP-Version');
    header('Access-Control-Max-Age: 86400');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Content-Type: application/json; charset=UTF-8');
}

setCorsHeaders();

// Gestione preflight OPTIONS
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

// Solo POST è accettato
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    jsonError('Method not allowed', 405);
}

// =====================================================================
// Rate Limiting (basato su file, senza dipendenze esterne)
// =====================================================================

function checkRateLimit(): void
{
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $cacheFile = CACHE_DIR . 'rl_' . md5($ip) . '.json';

    if (!is_dir(CACHE_DIR)) {
        mkdir(CACHE_DIR, 0755, true);
    }

    $now = time();
    $data = ['count' => 0, 'window_start' => $now];

    if (file_exists($cacheFile)) {
        $stored = json_decode(file_get_contents($cacheFile), true);
        if ($stored && ($now - $stored['window_start']) < RATE_LIMIT_WINDOW) {
            $data = $stored;
        }
    }

    $data['count']++;

    if ($data['count'] > RATE_LIMIT_REQUESTS) {
        jsonError('Rate limit exceeded', 429);
    }

    file_put_contents($cacheFile, json_encode($data), LOCK_EX);
}

checkRateLimit();

// =====================================================================
// Cache Helper
// =====================================================================

function getCached(string $key): ?array
{
    if (!CACHE_ENABLED) return null;

    $cacheFile = CACHE_DIR . 'cache_' . md5($key) . '.json';
    if (!file_exists($cacheFile)) return null;

    $data = json_decode(file_get_contents($cacheFile), true);
    if (!$data || (time() - $data['ts']) > CACHE_TTL) {
        @unlink($cacheFile);
        return null;
    }

    return $data['payload'];
}

function setCache(string $key, array $payload): void
{
    if (!CACHE_ENABLED) return;

    if (!is_dir(CACHE_DIR)) {
        mkdir(CACHE_DIR, 0755, true);
    }

    $cacheFile = CACHE_DIR . 'cache_' . md5($key) . '.json';
    file_put_contents($cacheFile, json_encode(['ts' => time(), 'payload' => $payload]), LOCK_EX);
}

// =====================================================================
// HTTP Client Helper
// =====================================================================

function httpPost(string $url, array $data, array $headers = []): ?array
{
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => json_encode($data),
        CURLOPT_HTTPHEADER     => array_merge(['Content-Type: application/json'], $headers),
        CURLOPT_TIMEOUT        => 10,
        CURLOPT_SSL_VERIFYPEER => true,
    ]);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($response === false || $httpCode >= 400) {
        return null;
    }

    return json_decode($response, true);
}

function httpGet(string $url, array $headers = []): ?array
{
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER     => $headers,
        CURLOPT_TIMEOUT        => 10,
        CURLOPT_SSL_VERIFYPEER => true,
    ]);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($response === false || $httpCode >= 400) {
        return null;
    }

    return json_decode($response, true);
}

// =====================================================================
// Response Helpers
// =====================================================================

function jsonSuccess(array $data): void
{
    echo json_encode(['success' => true, 'data' => $data]);
    exit;
}

function jsonError(string $message, int $code = 400): void
{
    http_response_code($code);
    echo json_encode(['success' => false, 'error' => $message]);
    exit;
}

// =====================================================================
// Logging
// =====================================================================

function nmpLog(string $level, string $message): void
{
    if (!LOG_ENABLED) return;

    $levels = ['DEBUG' => 0, 'INFO' => 1, 'WARNING' => 2, 'ERROR' => 3];
    $configLevel = $levels[LOG_LEVEL] ?? 2;
    $msgLevel = $levels[$level] ?? 1;

    if ($msgLevel < $configLevel) return;

    $logDir = dirname(LOG_FILE);
    if (!is_dir($logDir)) {
        mkdir($logDir, 0755, true);
    }

    $line = sprintf("[%s] [%s] %s\n", date('Y-m-d H:i:s'), $level, $message);
    file_put_contents(LOG_FILE, $line, FILE_APPEND | LOCK_EX);
}
