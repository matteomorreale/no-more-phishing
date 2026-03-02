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
      
      // FIX: L'API restituisce { success: true, data: { ... } }
      if (data.success && data.data) {
          return data.data;
      }
      
      // Fallback per compatibilità se l'API cambiasse
      if (data.results) {
          return data;
      }

      return { results: [], hasThreats: false, error: 'Invalid response format' };

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

    // Normalizza il dominio
    const cleanDomain = domain.toLowerCase().trim();

    // LISTA DOMINI NOTI E AFFIDABILI (Fallback locale)
    // Se l'API fallisce o non conosce il dominio, ma è uno di questi,
    // lo consideriamo "clean" (pulito) per evitare falsi positivi "Unknown".
    const KNOWN_LEGIT_DOMAINS = [
      'gmail.com', 'googlemail.com', 'yahoo.com', 'ymail.com', 
      'hotmail.com', 'outlook.com', 'live.com', 'msn.com', 
      'aol.com', 'icloud.com', 'me.com', 'mac.com', 
      'gmx.com', 'mail.com', 'libero.it', 'virgilio.it', 
      'tiscali.it', 'alice.it', 'tim.it', 'fastwebnet.it',
      'poste.it', 'aruba.it', 'pec.it', 'legalmail.it'
    ];

    try {
      const response = await fetch(`${this.baseUrl}check-domain.php`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-NMP-Version': '1.0.0',
        },
        body: JSON.stringify({ domain: cleanDomain }),
      });

      if (!response.ok) {
        console.warn('[NMP] Proxy domain check failed:', response.status);
        // Fallback su lista nota
        if (KNOWN_LEGIT_DOMAINS.includes(cleanDomain)) {
            return { reputation: 'clean', isBlacklisted: false, source: 'local_fallback' };
        }
        return { reputation: 'unknown', isBlacklisted: false, error: `HTTP ${response.status}` };
      }

      const data = await response.json();
      
      // FIX: L'API restituisce { success: true, data: { ... } }
      let result = data;
      if (data.success && data.data) {
          result = data.data;
      }
      
      // Se l'API restituisce unknown ma è un dominio noto, forziamo clean
      if (result.reputation === 'unknown' && KNOWN_LEGIT_DOMAINS.includes(cleanDomain)) {
          return { ...result, reputation: 'clean', source: 'local_override' };
      }

      return result;

    } catch (error) {
      console.warn('[NMP] Proxy domain check error:', error.message);
      
      // Fallback su lista nota in caso di errore di rete
      if (KNOWN_LEGIT_DOMAINS.includes(cleanDomain)) {
          return { reputation: 'clean', isBlacklisted: false, source: 'local_fallback_error' };
      }

      return { reputation: 'unknown', isBlacklisted: false, error: error.message };
    }
  }
}
