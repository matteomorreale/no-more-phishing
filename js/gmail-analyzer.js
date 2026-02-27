/**
 * No More Phishing - Gmail Analyzer
 * @author Matteo Morreale
 * @version 1.0.0
 *
 * Recupera e analizza i dati delle email tramite la Gmail API.
 * Supporta sia messaggi singoli che thread.
 */

export class GmailAnalyzer {
  constructor(authToken, apiBase) {
    this.authToken = authToken;
    this.apiBase = apiBase;
  }

  // ===================================================================
  // Analisi di un singolo messaggio
  // ===================================================================

  async analyzeMessage(messageId) {
    const message = await this._fetchMessage(messageId);
    return this._parseMessage(message);
  }

  // ===================================================================
  // Analisi di un thread completo
  // ===================================================================

  async analyzeThread(threadId) {
    const thread = await this._fetchThread(threadId);
    const messages = thread.messages || [];

    if (messages.length === 0) {
      throw new Error('Thread vuoto');
    }

    // Analizza il primo messaggio del thread (il più importante per sicurezza)
    const firstMessageData = this._parseMessage(messages[0]);

    // Raccoglie URL da tutti i messaggi del thread
    const allUrls = new Set(firstMessageData.urls);
    for (let i = 1; i < messages.length; i++) {
      const msgData = this._parseMessage(messages[i]);
      msgData.urls.forEach(url => allUrls.add(url));
    }

    return {
      ...firstMessageData,
      urls: Array.from(allUrls),
      isThread: true,
      messageCount: messages.length,
    };
  }

  // ===================================================================
  // Parsing del messaggio Gmail
  // ===================================================================

  _parseMessage(message) {
    const headers = this._extractHeaders(message.payload?.headers || []);
    const authResults = this._parseAuthResults(headers['authentication-results'] || '');
    const body = this._extractBody(message.payload);
    const urls = this._extractUrls(body);
    const urgencyKeywords = this._detectUrgencyKeywords(body, headers['subject'] || '');
    const sender = headers['from'] || '';
    const senderDomain = this._extractDomain(sender);
    const envelopeDomain = this._extractEnvelopeDomain(headers['received'] || '');
    const senderDomainMatch = envelopeDomain
      ? senderDomain.toLowerCase() === envelopeDomain.toLowerCase()
      : null;

    return {
      messageId: message.id,
      subject: headers['subject'] || '',
      sender,
      senderDomain,
      date: headers['date'] || '',
      replyTo: headers['reply-to'] || '',
      returnPath: headers['return-path'] || '',
      spf: authResults.spf,
      dkim: authResults.dkim,
      dmarc: authResults.dmarc,
      senderDomainMatch,
      urls,
      urgencyKeywords,
      hasAttachments: this._hasAttachments(message.payload),
      isReply: !!(headers['in-reply-to'] || headers['references']),
      rawHeaders: headers,
    };
  }

  // ===================================================================
  // Estrazione Header
  // ===================================================================

  _extractHeaders(headersList) {
    const headers = {};
    for (const header of headersList) {
      headers[header.name.toLowerCase()] = header.value;
    }
    return headers;
  }

  // ===================================================================
  // Parsing Authentication-Results (SPF, DKIM, DMARC)
  // ===================================================================

  _parseAuthResults(authResultsHeader) {
    const result = {
      spf: 'none',
      dkim: 'none',
      dmarc: 'none',
    };

    if (!authResultsHeader) return result;

    // SPF
    const spfMatch = authResultsHeader.match(/spf=(\w+)/i);
    if (spfMatch) result.spf = spfMatch[1].toLowerCase();

    // DKIM
    const dkimMatch = authResultsHeader.match(/dkim=(\w+)/i);
    if (dkimMatch) result.dkim = dkimMatch[1].toLowerCase();

    // DMARC
    const dmarcMatch = authResultsHeader.match(/dmarc=(\w+)/i);
    if (dmarcMatch) result.dmarc = dmarcMatch[1].toLowerCase();

    return result;
  }

  // ===================================================================
  // Estrazione corpo email (testo e HTML)
  // ===================================================================

  _extractBody(payload) {
    if (!payload) return '';

    let body = '';

    const decodeBase64 = (data) => {
      try {
        return atob(data.replace(/-/g, '+').replace(/_/g, '/'));
      } catch {
        return '';
      }
    };

    const extractFromPart = (part) => {
      if (!part) return;
      if (part.mimeType === 'text/plain' || part.mimeType === 'text/html') {
        if (part.body?.data) {
          body += decodeBase64(part.body.data) + '\n';
        }
      }
      if (part.parts) {
        part.parts.forEach(extractFromPart);
      }
    };

    if (payload.body?.data) {
      body = decodeBase64(payload.body.data);
    } else if (payload.parts) {
      payload.parts.forEach(extractFromPart);
    }

    return body;
  }

  // ===================================================================
  // Estrazione URL dal corpo dell'email
  // ===================================================================

  _extractUrls(body) {
    const urlRegex = /https?:\/\/[^\s"'<>)\]]+/gi;
    const matches = body.match(urlRegex) || [];
    // Rimuovi duplicati e URL di Google (tracking interno)
    const unique = [...new Set(matches)];
    return unique.filter(url => {
      try {
        const parsed = new URL(url);
        // Esclude URL di Google stessi (tracking, immagini, ecc.)
        const googleDomains = ['google.com', 'googleapis.com', 'gstatic.com', 'googleusercontent.com'];
        return !googleDomains.some(d => parsed.hostname.endsWith(d));
      } catch {
        return false;
      }
    }).slice(0, 50); // Limita a 50 URL per performance
  }

  // ===================================================================
  // Rilevamento parole chiave di urgenza/phishing
  // ===================================================================

  _detectUrgencyKeywords(body, subject) {
    const text = (body + ' ' + subject).toLowerCase();
    const keywords = [
      // Italiano
      'urgente', 'immediato', 'scadenza', 'verifica il tuo account',
      'sospeso', 'bloccato', 'accedi ora', 'clicca qui', 'conferma',
      'aggiorna i tuoi dati', 'password scaduta', 'attività sospetta',
      // Inglese
      'urgent', 'immediate', 'verify your account', 'suspended',
      'blocked', 'click here', 'confirm now', 'update your information',
      'password expired', 'suspicious activity', 'act now', 'limited time',
      'your account has been', 'unusual sign-in', 'security alert',
      'you have been selected', 'congratulations', 'winner',
    ];
    const found = keywords.filter(kw => text.includes(kw));
    return found;
  }

  // ===================================================================
  // Estrazione dominio dal campo From
  // ===================================================================

  _extractDomain(fromHeader) {
    if (!fromHeader) return '';
    const emailMatch = fromHeader.match(/<([^>]+)>/) || fromHeader.match(/([^\s]+@[^\s]+)/);
    if (emailMatch) {
      const email = emailMatch[1];
      const parts = email.split('@');
      return parts.length > 1 ? parts[1].trim().toLowerCase() : '';
    }
    return '';
  }

  // ===================================================================
  // Estrazione dominio mittente dall'header Received
  // ===================================================================

  _extractEnvelopeDomain(receivedHeader) {
    if (!receivedHeader) return null;
    const match = receivedHeader.match(/from\s+[\w.-]+\s+\([\w.-]+\s+\[[\d.]+\]\)/i);
    if (match) {
      const domainMatch = match[0].match(/from\s+([\w.-]+)/i);
      if (domainMatch) return domainMatch[1];
    }
    return null;
  }

  // ===================================================================
  // Verifica allegati
  // ===================================================================

  _hasAttachments(payload) {
    if (!payload) return false;
    if (payload.parts) {
      return payload.parts.some(part =>
        part.filename && part.filename.length > 0
      );
    }
    return false;
  }

  // ===================================================================
  // Chiamate API Gmail
  // ===================================================================

  async _fetchMessage(messageId) {
    const response = await fetch(
      `${this.apiBase}messages/${messageId}?format=full`,
      {
        headers: { Authorization: `Bearer ${this.authToken}` }
      }
    );
    if (!response.ok) {
      throw new Error(`Gmail API error: ${response.status}`);
    }
    return response.json();
  }

  async _fetchThread(threadId) {
    const response = await fetch(
      `${this.apiBase}threads/${threadId}?format=full`,
      {
        headers: { Authorization: `Bearer ${this.authToken}` }
      }
    );
    if (!response.ok) {
      throw new Error(`Gmail API error: ${response.status}`);
    }
    return response.json();
  }
}
