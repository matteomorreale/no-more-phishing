<?php
/**
 * No More Phishing - URL Check Endpoint
 * @author Matteo Morreale
 * @version 1.0.0
 *
 * Analizza una lista di URL tramite:
 * - Google Safe Browsing API v4
 * - VirusTotal API v3
 *
 * POST /check-urls.php
 * Body: { "urls": ["https://example.com", ...] }
 */

require_once __DIR__ . '/bootstrap.php';

// =====================================================================
// Input Validation
// =====================================================================

$body = json_decode(file_get_contents('php://input'), true);

if (!isset($body['urls']) || !is_array($body['urls'])) {
    jsonError('Invalid request: urls array required');
}

$urls = array_filter($body['urls'], function ($url) {
    return filter_var($url, FILTER_VALIDATE_URL) !== false;
});

$urls = array_values(array_unique(array_slice($urls, 0, 50)));

if (empty($urls)) {
    jsonSuccess(['results' => [], 'hasThreats' => false]);
}

// =====================================================================
// Analisi
// =====================================================================

$results = [];
$hasThreats = false;

// Controlla cache per ogni URL
$uncachedUrls = [];
foreach ($urls as $url) {
    $cacheKey = 'url_' . $url;
    $cached = getCached($cacheKey);
    if ($cached !== null) {
        $results[$url] = $cached;
        if ($cached['isMalicious']) $hasThreats = true;
    } else {
        $uncachedUrls[] = $url;
    }
}

// =====================================================================
// 1. Google Safe Browsing (batch)
// =====================================================================

if (!empty($uncachedUrls) && GOOGLE_SAFE_BROWSING_API_KEY !== 'YOUR_GOOGLE_SAFE_BROWSING_API_KEY') {
    $gsbResults = checkGoogleSafeBrowsing($uncachedUrls);
    foreach ($gsbResults as $url => $isMalicious) {
        if (!isset($results[$url])) {
            $results[$url] = [
                'url'         => $url,
                'isMalicious' => $isMalicious,
                'sources'     => $isMalicious ? ['google_safe_browsing'] : [],
                'threats'     => [],
            ];
        }
    }
}

// =====================================================================
// 2. VirusTotal (per URL non ancora marcati come malevoli)
// =====================================================================

if (VIRUSTOTAL_API_KEY !== 'YOUR_VIRUSTOTAL_API_KEY') {
    foreach ($uncachedUrls as $url) {
        if (isset($results[$url]) && $results[$url]['isMalicious']) continue;

        $vtResult = checkVirusTotal($url);
        if ($vtResult !== null) {
            if (!isset($results[$url])) {
                $results[$url] = [
                    'url'         => $url,
                    'isMalicious' => false,
                    'sources'     => [],
                    'threats'     => [],
                ];
            }
            if ($vtResult['isMalicious']) {
                $results[$url]['isMalicious'] = true;
                $results[$url]['sources'][] = 'virustotal';
                $results[$url]['threats'] = array_merge($results[$url]['threats'], $vtResult['threats']);
            }
        }
    }
}

// =====================================================================
// Completa i risultati mancanti e aggiorna cache
// =====================================================================

foreach ($uncachedUrls as $url) {
    if (!isset($results[$url])) {
        $results[$url] = [
            'url'         => $url,
            'isMalicious' => false,
            'sources'     => [],
            'threats'     => [],
        ];
    }

    if ($results[$url]['isMalicious']) $hasThreats = true;

    // Salva in cache
    setCache('url_' . $url, $results[$url]);
}

jsonSuccess([
    'results'    => array_values($results),
    'hasThreats' => $hasThreats,
    'total'      => count($results),
    'malicious'  => count(array_filter($results, fn($r) => $r['isMalicious'])),
]);

// =====================================================================
// Funzioni di analisi
// =====================================================================

function checkGoogleSafeBrowsing(array $urls): array
{
    $threatEntries = array_map(fn($url) => ['url' => $url], $urls);

    $payload = [
        'client'     => ['clientId' => 'no-more-phishing', 'clientVersion' => '1.0.0'],
        'threatInfo' => [
            'threatTypes'      => ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
            'platformTypes'    => ['ANY_PLATFORM'],
            'threatEntryTypes' => ['URL'],
            'threatEntries'    => $threatEntries,
        ],
    ];

    $apiUrl = GOOGLE_SAFE_BROWSING_URL . '?key=' . GOOGLE_SAFE_BROWSING_API_KEY;
    $response = httpPost($apiUrl, $payload);

    $results = array_fill_keys($urls, false);

    if ($response && isset($response['matches'])) {
        foreach ($response['matches'] as $match) {
            $matchedUrl = $match['threat']['url'] ?? null;
            if ($matchedUrl && isset($results[$matchedUrl])) {
                $results[$matchedUrl] = true;
            }
        }
    }

    return $results;
}

function checkVirusTotal(string $url): ?array
{
    // Encode URL in base64 (richiesto da VirusTotal API v3)
    $urlId = rtrim(base64_encode($url), '=');

    $response = httpGet(
        VIRUSTOTAL_URL_REPORT_URL . '/' . $urlId,
        [
            'x-apikey: ' . VIRUSTOTAL_API_KEY,
            'Accept: application/json',
        ]
    );

    if (!$response || !isset($response['data']['attributes']['last_analysis_stats'])) {
        return null;
    }

    $stats = $response['data']['attributes']['last_analysis_stats'];
    $malicious = ($stats['malicious'] ?? 0) + ($stats['suspicious'] ?? 0);
    $isMalicious = $malicious >= 2; // Soglia: almeno 2 engine lo segnalano

    $threats = [];
    if ($isMalicious && isset($response['data']['attributes']['last_analysis_results'])) {
        foreach ($response['data']['attributes']['last_analysis_results'] as $engine => $result) {
            if (in_array($result['category'], ['malicious', 'suspicious'], true)) {
                $threats[] = $engine;
            }
        }
    }

    return [
        'isMalicious' => $isMalicious,
        'threats'     => array_slice($threats, 0, 5),
        'stats'       => $stats,
    ];
}
