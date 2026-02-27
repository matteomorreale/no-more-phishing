/**
 * No More Phishing - Proxy Client
 * @author Matteo Morreale
 * @version 1.0.0
 *
 * Gestisce la comunicazione con il backend proxy PHP per
 * l'analisi degli URL e dei domini tramite API esterne.
 */

export class ProxyClient {
  constructor(baseUrl) {
    this.baseUrl = baseUrl.endsWith('/') ? baseUrl : baseUrl + '/';
  }

  // ===================================================================
  // Analisi URL con Google Safe Browsing, VirusTotal e URLScan
  // ===================================================================

  async checkUrls(urls) {
    if (!urls || urls.length === 0) {
      return { results: [], hasThreats: false };
    }

    try {
      const response = await fetch(`${this.baseUrl}check-urls.php`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-NMP-Version': '1.0.0',
        },
        body: JSON.stringify({ urls }),
      });

      if (!response.ok) {
        console.warn('[NMP] Proxy URL check failed:', response.status);
        return { results: [], hasThreats: false, error: `HTTP ${response.status}` };
      }

      const data = await response.json();
      return data;

    } catch (error) {
      console.warn('[NMP] Proxy URL check error:', error.message);
      return { results: [], hasThreats: false, error: error.message };
    }
  }

  // ===================================================================
  // Analisi reputazione dominio
  // ===================================================================

  async checkDomain(domain) {
    if (!domain) {
      return { reputation: 'unknown', isBlacklisted: false };
    }

    try {
      const response = await fetch(`${this.baseUrl}check-domain.php`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-NMP-Version': '1.0.0',
        },
        body: JSON.stringify({ domain }),
      });

      if (!response.ok) {
        console.warn('[NMP] Proxy domain check failed:', response.status);
        return { reputation: 'unknown', isBlacklisted: false, error: `HTTP ${response.status}` };
      }

      const data = await response.json();
      return data;

    } catch (error) {
      console.warn('[NMP] Proxy domain check error:', error.message);
      return { reputation: 'unknown', isBlacklisted: false, error: error.message };
    }
  }
}
