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
    const sensitiveData = this._detectSensitiveKeywords(body, headers['subject'] || '');
    const bodyEmails = this._extractBodyEmails(body);
    
    // Domain Match Logic Migliorata
    let senderDomainMatch = false;
    
    // 1. Controlla Received headers (potrebbero essere multipli)
    const receivedHeaders = Array.isArray(headers['received']) 
        ? headers['received'] 
        : (headers['received'] ? [headers['received']] : []);

    const matchFound = receivedHeaders.some(header => {
        const envDomain = this._extractEnvelopeDomain(header);
        // Controlla se il dominio envelope contiene il dominio sender (es. mail.qdopp.com contiene qdopp.com)
        return envDomain && (
            envDomain.toLowerCase() === senderDomain.toLowerCase() ||
            envDomain.toLowerCase().endsWith('.' + senderDomain.toLowerCase()) ||
            senderDomain.toLowerCase().endsWith('.' + envDomain.toLowerCase())
        );
    });

    // 2. Se SPF è PASS, consideriamo il dominio verificato anche se Received è confuso
    if (authResults.spf === 'pass' || matchFound) {
        senderDomainMatch = true;
    }

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
      sensitiveData,
      bodyEmails,
    };
  }

  // ===================================================================
  // Estrazione Header
  // ===================================================================

  _extractHeaders(headersList) {
    const headers = {};
    for (const header of headersList) {
      const name = header.name.toLowerCase();
      // Gestione header multipli (es. Received)
      if (headers[name]) {
          if (Array.isArray(headers[name])) {
              headers[name].push(header.value);
          } else {
              headers[name] = [headers[name], header.value];
          }
      } else {
          headers[name] = header.value;
      }
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

    // FIX: Se authResultsHeader è un array (più header), prendiamo il primo (più recente)
    // o li uniamo. Solitamente il primo è quello aggiunto dal server ricevente (Google).
    let headerValue = '';
    if (Array.isArray(authResultsHeader)) {
        headerValue = String(authResultsHeader[0]); 
    } else {
        headerValue = String(authResultsHeader);
    }

    // SPF
    const spfMatch = headerValue.match(/spf=(\w+)/i);
    if (spfMatch) result.spf = spfMatch[1].toLowerCase();

    // DKIM
    const dkimMatch = headerValue.match(/dkim=(\w+)/i);
    if (dkimMatch) result.dkim = dkimMatch[1].toLowerCase();

    // DMARC
    const dmarcMatch = headerValue.match(/dmarc=(\w+)/i);
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
        // Base64Url decode
        const decoded = atob(data.replace(/-/g, '+').replace(/_/g, '/'));
        
        // Decodifica UTF-8 corretta (evita problemi con caratteri speciali)
        const bytes = new Uint8Array(decoded.length);
        for (let i = 0; i < decoded.length; i++) {
            bytes[i] = decoded.charCodeAt(i);
        }
        return new TextDecoder().decode(bytes);
      } catch (e) {
        console.warn('[NMP] Decode error:', e);
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
    // 0. Pre-process: Decodifica caratteri di escape JSON/Unicode
    // Il raw body a volte contiene escape come \u003c (per <) o \" (per ")
    let cleanBody = body;
    try {
        // Log pre-clean
        console.log('[NMP] Raw body length:', body.length);
        console.log('[NMP] Raw body preview:', body.substring(0, 200));

        // Rimuove backslash di escape
        cleanBody = cleanBody.replace(/\\"/g, '"').replace(/\\n/g, '\n').replace(/\\r/g, '');
        // Decodifica unicode escape sequence (es. \u003c -> <)
        cleanBody = cleanBody.replace(/\\u([\d\w]{4})/gi, (match, grp) => {
            return String.fromCharCode(parseInt(grp, 16));
        });

        // Log post-clean
        console.log('[NMP] Clean body length:', cleanBody.length);
        console.log('[NMP] Clean body preview:', cleanBody.substring(0, 200));
    } catch (e) {
        console.warn('[NMP] Body unescape failed:', e);
    }

    // 1. Estrazione tramite DOMParser (per link reali <a href>)
    let domUrls = [];
    if (typeof DOMParser !== 'undefined') {
        try {
            const parser = new DOMParser();
            // Wrap body in case it's just text
            const doc = parser.parseFromString(cleanBody, 'text/html');
            const anchors = doc.querySelectorAll('a[href]');
            domUrls = Array.from(anchors).map(a => a.href);
            console.log('[NMP] DOMParser found URLs:', domUrls.length, domUrls);
        } catch (e) {
            console.warn('[NMP] DOMParser extraction failed:', e);
        }
    }

    // 2. Estrazione tramite Regex (fallback per plain text o link non cliccabili)
    // Aggiornato per includere mailto: e gestire meglio i confini
    // Regex più permissiva per catturare URL spezzati o formattati male
    const urlRegex = /(?:https?|ftp|mailto):\/?[^\s"'<>)\]]+/gi;
    const regexMatches = cleanBody.match(urlRegex) || [];
    console.log('[NMP] Regex found URLs:', regexMatches.length, regexMatches);
    
    // Combina i risultati
    const allMatches = [...domUrls, ...regexMatches];
    
    // Rimuovi duplicati e URL di Google (tracking interno)
    const unique = [...new Set(allMatches)];
    return unique.filter(url => {
      try {
        // Pulizia finale URL (rimuove eventuali backslash residui alla fine)
        url = url.replace(/\\$/, '');

        // Gestione speciale per mailto
        if (url.startsWith('mailto:')) return true;
        
        const parsed = new URL(url);
        // Esclude URL di Google stessi (tracking, immagini, ecc.)
        const googleDomains = ['google.com', 'googleapis.com', 'gstatic.com', 'googleusercontent.com', 'ggpht.com'];
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
    
    // Lista estesa di parole chiave in più lingue (IT, EN, ES, FR, DE)
    // Raggruppate per categoria semantica per facilitare la manutenzione
    const keywords = [
      // 1. URGENZA / SCADENZA / AZIONE IMMEDIATA
      // IT
      'urgente', 'immediato', 'scadenza', 'agisci ora', 'ultimo avviso', 'tempo limitato', 'non ignorare',
      'rispondi subito', 'attenzione richiesta', 'immediata attenzione', 'scade oggi',
      // EN
      'urgent', 'immediate', 'deadline', 'act now', 'final notice', 'limited time', 'do not ignore',
      'respond immediately', 'attention required', 'immediate attention', 'expires today', 'asap',
      // ES
      'urgente', 'inmediato', 'plazo', 'actúe ahora', 'aviso final', 'tiempo limitado', 'no ignorar',
      'responda inmediatamente', 'atención requerida', 'atención inmediata', 'vence hoy',
      // FR
      'urgent', 'immédiat', 'date limite', 'agissez maintenant', 'dernier avis', 'temps limité', 'ne pas ignorer',
      'répondez immédiatement', 'attention requise', 'attention immédiate', 'expire aujourd\'hui',
      // DE
      'dringend', 'sofort', 'frist', 'handeln sie jetzt', 'letzte mahnung', 'begrenzte zeit', 'nicht ignorieren',
      'antworten sie sofort', 'achtung erforderlich', 'sofortige aufmerksamkeit', 'läuft heute ab',

      // 2. ACCOUNT / SICUREZZA / VERIFICA
      // IT
      'verifica il tuo account', 'account sospeso', 'account bloccato', 'accesso non autorizzato', 'conferma identità',
      'aggiorna i tuoi dati', 'password scaduta', 'attività sospetta', 'sicurezza compromessa', 'riattiva account',
      'il tuo account è stato', 'tentativo di accesso', 'proteggi il tuo account', 'conferma le tue credenziali',
      // EN
      'verify your account', 'account suspended', 'account blocked', 'unauthorized access', 'confirm identity',
      'update your information', 'password expired', 'suspicious activity', 'security compromised', 'reactivate account',
      'your account has been', 'login attempt', 'protect your account', 'confirm your credentials', 'unusual sign-in',
      'security alert', 'validate account',
      // ES
      'verifique su cuenta', 'cuenta suspendida', 'cuenta bloqueada', 'acceso no autorizado', 'confirmar identidad',
      'actualice su información', 'contraseña caducada', 'actividad sospechosa', 'seguridad comprometida', 'reactivar cuenta',
      'su cuenta ha sido', 'intento de inicio de sesión', 'proteja su cuenta', 'confirme sus credenciales',
      // FR
      'vérifiez votre compte', 'compte suspendu', 'compte bloqué', 'accès non autorisé', 'confirmer l\'identité',
      'mettez à jour vos informations', 'mot de passe expiré', 'activité suspecte', 'sécurité compromise', 'réactiver le compte',
      'votre compte a été', 'tentative de connexion', 'protégez votre compte', 'confirmez vos identifiants',
      // DE
      'überprüfen sie ihr konto', 'konto gesperrt', 'konto blockiert', 'unbefugter zugriff', 'identität bestätigen',
      'aktualisieren sie ihre informationen', 'passwort abgelaufen', 'verdächtige aktivität', 'sicherheit gefährdet', 'konto reaktivieren',
      'ihr konto wurde', 'anmeldeversuch', 'schützen sie ihr konto', 'bestätigen sie ihre anmeldeinformationen',

      // 3. PAGAMENTI / FINANZA / PREMI
      // IT
      'pagamento fallito', 'fattura scaduta', 'rimborso in attesa', 'vincitore', 'congratulazioni', 'hai vinto',
      'pacco in attesa', 'spedizione bloccata', 'bonifico in arrivo', 'coordinate bancarie', 'carta di credito',
      // EN
      'payment failed', 'invoice overdue', 'refund pending', 'winner', 'congratulations', 'you won',
      'package pending', 'shipment on hold', 'transfer incoming', 'bank details', 'credit card',
      'lottery', 'prize', 'claim your prize', 'gift card',
      // ES
      'pago fallido', 'factura vencida', 'reembolso pendiente', 'ganador', 'felicidades', 'has ganado',
      'paquete pendiente', 'envío retenido', 'transferencia entrante', 'datos bancarios', 'tarjeta de crédito',
      // FR
      'paiement échoué', 'facture impayée', 'remboursement en attente', 'gagnant', 'félicitations', 'vous avez gagné',
      'colis en attente', 'expédition retenue', 'virement entrant', 'coordonnées bancaires', 'carte de crédit',
      // DE
      'zahlung fehlgeschlagen', 'rechnung überfällig', 'rückerstattung ausstehend', 'gewinner', 'herzlichen glückwunsch', 'sie haben gewonnen',
      'paket ausstehend', 'sendung zurückgehalten', 'überweisung eingehend', 'bankverbindung', 'kreditkarte',

      // 4. AZIONI GENERICHE SOSPETTE
      // IT
      'clicca qui', 'scarica allegato', 'apri il file', 'compila il modulo', 'segui il link',
      // EN
      'click here', 'download attachment', 'open the file', 'fill out the form', 'follow the link', 'click below',
      // ES
      'haga clic aquí', 'descargar archivo adjunto', 'abrir el archivo', 'rellene el formulario', 'siga el enlace',
      // FR
      'cliquez ici', 'télécharger la pièce jointe', 'ouvrir le fichier', 'remplissez le formulaire', 'suivez le lien',
      // DE
      'hier klicken', 'anhang herunterladen', 'datei öffnen', 'formular ausfüllen', 'link folgen',
      // 5. LOTTERIA / DONAZIONI / EREDITÀ
      // IT
      'donazione', 'filantropo', 'eredità', 'beneficiario', 'somma di denaro', 'selezionato casualmente', 
      'vincita', 'lotteria', 'fortunato vincitore', 'i tuoi fondi', 'trasferimento bancario', 'milioni di dollari',
      // EN
      'donation', 'philanthropist', 'inheritance', 'beneficiary', 'sum of money', 'randomly selected', 
      'winning', 'lottery', 'lucky winner', 'your funds', 'bank transfer', 'million dollars', 'giving while living',
      'share my wealth', 'charity project',
      // ES
      'donación', 'filántropo', 'herencia', 'beneficiario', 'suma de dinero', 'seleccionado al azar',
      'ganador', 'lotería', 'afortunado ganador', 'sus fondos', 'transferencia bancaria', 'millones de dólares',
      // FR
      'donation', 'philanthrope', 'héritage', 'bénéficiaire', 'somme d\'argent', 'sélectionné au hasard',
      'gagnant', 'loterie', 'heureux gagnant', 'vos fonds', 'virement bancaire', 'millions de dollars',
      // DE
      'spende', 'philanthrop', 'erbe', 'begünstigter', 'geldbetrag', 'zufällig ausgewählt',
      'gewinner', 'lotterie', 'glücklicher gewinner', 'ihre gelder', 'banküberweisung', 'millionen dollar',
    ];
    
    // Rimuovi duplicati e pulisci
    const uniqueKeywords = [...new Set(keywords)];
    
    // Cerca corrispondenze
    const found = uniqueKeywords.filter(kw => text.includes(kw));

    // Rilevamento importi monetari elevati nel soggetto o corpo
    // Pattern: Simboli valuta seguiti da numeri grandi, o "X million/billion"
    const moneyRegex = /(?:\$|€|£|usd|eur|gbp)\s?[\d,.]+\s*(?:million|billion|m|b|milioni|miliardi)?/i;
    const largeMoneyMatch = text.match(moneyRegex);
    if (largeMoneyMatch) {
        // Verifica se sembra un importo elevato (euristica base: contiene '000' o parole 'million'/'miliardi')
        if (largeMoneyMatch[0].includes('000') || /million|billion|milion|miliard/i.test(largeMoneyMatch[0])) {
            found.push('suspicious_amount_detected');
        }
    }

    return found;
  }

  // ===================================================================
  // Rilevamento richieste dati sensibili
  // ===================================================================

  _detectSensitiveKeywords(body, subject) {
    const text = (body + ' ' + subject).toLowerCase();
    
    const sensitiveKeywords = [
        // DOCUMENTI / IDENTITÀ
        'documento', 'passaporto', 'carta d\'identità', 'patente', 'codice fiscale', 'tessera sanitaria',
        'document', 'passport', 'identity card', 'id card', 'driving license', 'ssn', 'social security',
        
        // CREDENZIALI / PASSWORD
        'password', 'pin', 'credenziali', 'login', 'nome utente', 'username', 'codice di accesso',
        'credentials', 'access code', 'security code',
        
        // DATI BANCARI / FINANZIARI
        'iban', 'numero di conto', 'carta di credito', 'scadenza carta', 'cvv', 'cvc',
        'account number', 'credit card', 'card expiration', 'routing number',
        
        // AZIONI SOSPETTE SPECIFICHE
        'inviare a', 'inviare una copia', 'allegare documento', 'foto del documento',
        'send to', 'send a copy', 'attach document', 'photo of id', 'reply to this email with'
    ];

    const found = sensitiveKeywords.filter(kw => text.includes(kw));
    return found;
  }

  // ===================================================================
  // Estrazione Email dal corpo del messaggio
  // ===================================================================

  _extractBodyEmails(body) {
    if (!body) return [];
    
    // Regex semplice per email
    const emailRegex = /[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9_-]+/gi;
    const matches = body.match(emailRegex) || [];
    
    // Pulisci e normalizza
    const unique = [...new Set(matches.map(e => e.toLowerCase()))];
    return unique;
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
    // Rimuove eventuali prefissi come '#msg-f:'
    let cleanId = messageId.replace(/^#msg-f:/, '').replace(/^#thread-f:/, '');
    
    // Se è un numero decimale (solo cifre), convertilo in esadecimale
    if (/^\d+$/.test(cleanId)) {
       const original = cleanId;
       cleanId = BigInt(cleanId).toString(16);
       console.log('[NMP] Converted decimal ID:', original, 'to hex:', cleanId);
    }
    
    const url = `${this.apiBase}messages/${cleanId}?format=full`;
    console.log('[NMP] Fetching message from:', url);

    const response = await fetch(
      url,
      {
        headers: { Authorization: `Bearer ${this.authToken}` }
      }
    );
    if (!response.ok) {
      const errorBody = await response.text();
      console.error('[NMP] Gmail API error body:', errorBody);
      throw new Error(`Gmail API error: ${response.status} - ${errorBody}`);
    }
    return response.json();
  }

  async _fetchThread(threadId) {
    // Rimuove eventuali prefissi come '#thread-f:'
    let cleanId = threadId.replace(/^#thread-f:/, '');

    // Se è un numero decimale (solo cifre), convertilo in esadecimale
    if (/^\d+$/.test(cleanId)) {
       const original = cleanId;
       cleanId = BigInt(cleanId).toString(16);
       console.log('[NMP] Converted decimal ID:', original, 'to hex:', cleanId);
    }

    const url = `${this.apiBase}threads/${cleanId}?format=full`;
    console.log('[NMP] Fetching thread from:', url);

    const response = await fetch(
      url,
      {
        headers: { Authorization: `Bearer ${this.authToken}` }
      }
    );
    if (!response.ok) {
      const errorBody = await response.text();
      console.error('[NMP] Gmail API error body:', errorBody);
      throw new Error(`Gmail API error: ${response.status} - ${errorBody}`);
    }
    return response.json();
  }
}
