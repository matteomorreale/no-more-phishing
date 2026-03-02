<?php
/**
 * No More Phishing - Domain Check Endpoint
 * @author Matteo Morreale
 * @version 1.0.0
 *
 * Analizza la reputazione di un dominio tramite:
 * - VirusTotal API v3
 * - Google Safe Browsing API v4
 *
 * POST /check-domain.php
 * Body: { "domain": "example.com" }
 */

require_once __DIR__ . '/bootstrap.php';

// =====================================================================
// Input Validation
// =====================================================================

$body = json_decode(file_get_contents('php://input'), true);

if (!isset($body['domain']) || !is_string($body['domain'])) {
    jsonError('Invalid request: domain string required');
}

$domain = strtolower(trim($body['domain']));

// Validazione base del dominio
if (!preg_match('/^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z]{2,})+$/', $domain)) {
    jsonError('Invalid domain format');
}

// =====================================================================
// Controlla cache
// =====================================================================

$cacheKey = 'domain_' . $domain;
$cached = getCached($cacheKey);
if ($cached !== null) {
    jsonSuccess($cached);
}

// =====================================================================
// Analisi dominio
// =====================================================================

$result = [
    'domain'       => $domain,
    'reputation'   => 'unknown',
    'isBlacklisted' => false,
    'sources'      => [],
    'details'      => [],
];

// =====================================================================
// 1. VirusTotal Domain Report
// =====================================================================

if (VIRUSTOTAL_API_KEY !== 'YOUR_VIRUSTOTAL_API_KEY') {
    $vtResult = checkVirusTotalDomain($domain);
    if ($vtResult !== null) {
        $result['details']['virustotal'] = $vtResult;

        if ($vtResult['malicious'] >= 3) {
            $result['reputation'] = 'blacklisted';
            $result['isBlacklisted'] = true;
            $result['sources'][] = 'virustotal';
        } elseif ($vtResult['malicious'] >= 1 || $vtResult['suspicious'] >= 2) {
            $result['reputation'] = 'suspicious';
            $result['sources'][] = 'virustotal';
        } elseif ($vtResult['harmless'] > 0) {
            $result['reputation'] = 'clean';
        }
    }
}

// =====================================================================
// 2. Google Safe Browsing (controlla URL del dominio)
// =====================================================================

if (GOOGLE_SAFE_BROWSING_API_KEY !== 'YOUR_GOOGLE_SAFE_BROWSING_API_KEY') {
    $testUrls = [
        'https://' . $domain . '/',
        'http://' . $domain . '/',
    ];

    $gsbResult = checkGoogleSafeBrowsingDomain($testUrls);
    if ($gsbResult) {
        $result['isBlacklisted'] = true;
        $result['reputation'] = 'blacklisted';
        $result['sources'][] = 'google_safe_browsing';
    }
}

// =====================================================================
// Salva in cache e restituisci
// =====================================================================

setCache($cacheKey, $result);
jsonSuccess($result);

// =====================================================================
// Funzioni di analisi
// =====================================================================

function checkVirusTotalDomain(string $domain): ?array
{
    $response = httpGet(
        VIRUSTOTAL_DOMAIN_URL . urlencode($domain),
        [
            'x-apikey: ' . VIRUSTOTAL_API_KEY,
            'Accept: application/json',
        ]
    );

    if (!$response || !isset($response['data']['attributes']['last_analysis_stats'])) {
        return null;
    }

    $stats = $response['data']['attributes']['last_analysis_stats'];

    return [
        'malicious'  => $stats['malicious'] ?? 0,
        'suspicious' => $stats['suspicious'] ?? 0,
        'harmless'   => $stats['harmless'] ?? 0,
        'undetected' => $stats['undetected'] ?? 0,
        'reputation' => $response['data']['attributes']['reputation'] ?? 0,
        'categories' => $response['data']['attributes']['categories'] ?? [],
    ];
}

function checkGoogleSafeBrowsingDomain(array $urls): bool
{
    $threatEntries = array_map(fn($url) => ['url' => $url], $urls);

    $payload = [
        'client'     => ['clientId' => 'no-more-phishing', 'clientVersion' => '1.0.0'],
        'threatInfo' => [
            'threatTypes'      => ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
            'platformTypes'    => ['ANY_PLATFORM'],
            'threatEntryTypes' => ['URL'],
            'threatEntries'    => $threatEntries,
        ],
    ];

    $apiUrl = GOOGLE_SAFE_BROWSING_URL . '?key=' . GOOGLE_SAFE_BROWSING_API_KEY;
    $response = httpPost($apiUrl, $payload);

    return $response && !empty($response['matches']);
}
