/**
 * No More Phishing - Score Calculator
 * @author Matteo Morreale
 * @version 1.0.0
 *
 * Calcola il punteggio di affidabilità da 1 a 5 sulla base
 * dei parametri di sicurezza dell'email analizzata.
 */

export class ScoreCalculator {

  /**
   * Calcola il punteggio finale.
   * @param {Object} params - Parametri di analisi
   * @returns {{ score: number, details: Object }}
   */
  calculate(params) {
    const {
      spf,
      dkim,
      dmarc,
      senderDomainMatch,
      domainAnalysis,
      urlAnalysis,
      urgencyKeywords,
      hasAttachments,
      isReply,
      senderDomain,
      replyTo,
      urls,
      subject,
      messageCount,
      sensitiveData,
      bodyEmails,
    } = params;

    const details = {};
    let totalPenalty = 0;
    
    // Warning: punti di attenzione (max score 4)
    // Danger: punti critici (max score 3)
    let warningCount = 0;
    let dangerCount = 0;

    // ================================================================
    // 1. SPF (peso: 20 punti di penalità massima)
    // ================================================================
    const spfScore = this._scoreAuth(spf);
    details.spf = { value: spf, score: spfScore, label: this._authLabel(spf) };
    totalPenalty += (1 - spfScore) * 20;
    
    // Se SPF fallisce, è un Danger. Se è softfail/none, è Warning (ma none verrà gestito dopo come Danger per cap)
    if (spfScore === 0) dangerCount++;
    else if (spfScore < 1) warningCount++;

    // ================================================================
    // 2. DKIM (peso: 25 punti di penalità massima)
    // ================================================================
    const dkimScore = this._scoreAuth(dkim);
    details.dkim = { value: dkim, score: dkimScore, label: this._authLabel(dkim) };
    totalPenalty += (1 - dkimScore) * 25;

    // Se DKIM fallisce, è un Danger.
    if (dkimScore === 0) dangerCount++;
    else if (dkimScore < 1) warningCount++;

    // ================================================================
    // 3. DMARC (peso: 15 punti di penalità massima)
    // ================================================================
    const dmarcScore = this._scoreAuth(dmarc);
    details.dmarc = { value: dmarc, score: dmarcScore, label: this._authLabel(dmarc) };
    totalPenalty += (1 - dmarcScore) * 15;
    
    if (dmarcScore === 0) dangerCount++;
    else if (dmarcScore < 1) warningCount++;

    // ================================================================
    // 4. Corrispondenza dominio mittente (peso: 15 punti)
    // ================================================================
    if (senderDomainMatch === false) {
      details.senderDomainMatch = { match: false, penalty: 15 };
      totalPenalty += 15;
      dangerCount++; // Mismatch è sempre Danger
    } else {
      details.senderDomainMatch = { match: senderDomainMatch, penalty: 0 };
    }

    // ================================================================
    // 5. Reputazione dominio (peso: 20 punti)
    // ================================================================
    let domainPenalty = 0;

    // Controllo caratteri sospetti (Cyrillic, Homographs)
    // Se presenti, è DANGER immediato
    if (this._hasSuspiciousCharacters(senderDomain)) {
        domainPenalty += 50; // Penalità massiccia
        details.domainSuspiciousChars = true;
        dangerCount++;
    }

    // A. Analisi reputazione esterna
    if (domainAnalysis?.isBlacklisted) {
      domainPenalty += 20;
      dangerCount++;
    } else if (domainAnalysis?.reputation === 'suspicious') {
      domainPenalty += 10;
      dangerCount++;
    }

    // B. Analisi provider (Generic vs High Risk)
    let providerRisk = 'none';
    if (senderDomain) {
        const cleanSender = senderDomain.toLowerCase();
        
        if (this._isHighRiskProvider(cleanSender)) {
            providerRisk = 'high_risk';
            domainPenalty += 15; // Danger Malus
            dangerCount++;
        } else if (this._isGenericProvider(cleanSender)) {
            providerRisk = 'generic';
            domainPenalty += 5; // Warning Malus
            warningCount++;
        }
    }

    details.domain = { 
        reputation: domainAnalysis?.reputation || 'unknown', 
        providerRisk: providerRisk,
        penalty: domainPenalty 
    };
    totalPenalty += domainPenalty;

    // ================================================================
    // 6. URL malevoli e Mismatch Dominio (peso: 30 + 20 punti)
    // ================================================================
    const maliciousUrls = urlAnalysis?.results?.filter(r => r.isMalicious) || [];
    let urlPenalty = Math.min(maliciousUrls.length * 10, 30);
    
    if (maliciousUrls.length > 0) {
        dangerCount += maliciousUrls.length;
    }

    // Link Domain Mismatch Check e Suspicious Characters Check
    let mismatchCount = 0;
    let suspiciousLinksCount = 0;

    if (urls && urls.length > 0 && senderDomain) {
      const cleanSender = senderDomain.toLowerCase();
      
      urls.forEach(url => {
         const domain = this._extractDomain(url);
         // Ignora link interni o mailto
         if (!domain) return;
         
         // Controllo caratteri sospetti nel dominio del link
         if (this._hasSuspiciousCharacters(domain)) {
             suspiciousLinksCount++;
         }

         // Se il dominio del link è diverso dal sender (e non è sottodominio o dominio padre)
          if (domain !== cleanSender && 
              !domain.endsWith('.' + cleanSender) && 
              !cleanSender.endsWith('.' + domain)) {
              mismatchCount++;
          }
      });
    }
    
    // Penalità per mismatch: 5 punti per link diverso, max 20
    const mismatchPenalty = Math.min(mismatchCount * 5, 20);
    if (mismatchCount > 0) warningCount++; // Mismatch è Warning

    // Penalità per link con caratteri sospetti: 20 punti per link, max 60 (molto alto)
    const suspiciousLinksPenalty = Math.min(suspiciousLinksCount * 20, 60);
    if (suspiciousLinksCount > 0) dangerCount++; // Suspicious chars in link è Danger

    urlPenalty += mismatchPenalty + suspiciousLinksPenalty;

    details.urls = {
      total: urls?.length || (urlAnalysis?.results?.length || 0),
      malicious: maliciousUrls.length,
      mismatch: mismatchCount,
      suspiciousChars: suspiciousLinksCount,
      penalty: urlPenalty,
    };
    totalPenalty += urlPenalty;

    // ================================================================
    // 7. Parole chiave di urgenza/phishing (peso: 60 punti)
    // ================================================================
    // Aumentato notevolmente il peso: 15 punti per keyword, max 60.
    // Le parole chiave sono un indicatore molto forte di intenti malevoli.
    const urgencyPenalty = Math.min((urgencyKeywords?.length || 0) * 15, 60);
    details.urgency = {
      keywords: urgencyKeywords || [],
      count: urgencyKeywords?.length || 0,
      penalty: urgencyPenalty,
    };
    totalPenalty += urgencyPenalty;

    // ================================================================
    // 8. Allegati sospetti (peso: 5 punti bonus penalità)
    // ================================================================
    if (hasAttachments) {
      details.attachments = { present: true, penalty: 5 };
      totalPenalty += 5;
      warningCount++;
    } else {
      details.attachments = { present: false, penalty: 0 };
    }

    // ================================================================
    // Calcolo score finale (da 1 a 5)
    // ================================================================
    const maxPenalty = 170; // Aumentato max penalty teorico
    const normalizedPenalty = Math.min(totalPenalty / maxPenalty, 1);
    
    let rawScore = 5 - (normalizedPenalty * 4);
    let finalScore = Math.round(rawScore);

    // REGOLA STRICT: Se c'è una qualsiasi penalità, il punteggio non può essere 5
    // Questo garantisce "5/5 solo se c'è una totale pulizia"
    if (totalPenalty > 0 && finalScore === 5) {
      finalScore = 4;
    }

    // NUOVA REGOLA: Se SPF o DKIM sono 'none', il punteggio max è 3.
    // Anche se non falliscono esplicitamente, la mancanza di autenticazione è un rischio medio-alto.
    const spfStatus = (spf || 'none').toLowerCase();
    const dkimStatus = (dkim || 'none').toLowerCase();
    
    if (spfStatus === 'none' || dkimStatus === 'none') {
        dangerCount++; // Consideriamo Auth Missing come Danger
        details.scoreCapReason = 'auth_missing';
    }

    // NUOVA REGOLA: Se il dominio di Reply-To è diverso dal Sender, il punteggio max è 3.
    // Spesso usato nel phishing (CEO Fraud, BEC) per deviare la risposta.
    if (replyTo && senderDomain) {
        const replyToDomain = this._extractEmailDomain(replyTo);
        if (replyToDomain) {
             const cleanSender = senderDomain.toLowerCase();
             // Se i domini sono diversi e non sono uno sottodominio dell'altro
             if (replyToDomain !== cleanSender && 
                 !replyToDomain.endsWith('.' + cleanSender) && 
                 !cleanSender.endsWith('.' + replyToDomain)) {
                 
                 dangerCount++;
                 details.scoreCapReason = 'reply_to_mismatch';
                 details.replyToDomain = replyToDomain;
             }
        }
    }

    // NUOVA REGOLA (Anti-Scam): Se rileviamo contenuti testuali sospetti (keywords),
    // il punteggio deve crollare. Non può essere "Affidabile" se parla di vincite milionarie.
    if (urgencyKeywords && urgencyKeywords.length > 0) {
        const hasMoney = urgencyKeywords.includes('suspicious_amount_detected');
        
        // Se c'è un importo sospetto o molte keyword, è quasi certamente scam -> Danger
        if (hasMoney || urgencyKeywords.length >= 2) {
             dangerCount++;
             details.scoreCapReason = 'scam_content_high_risk';
        } else {
             // Altrimenti è comunque sospetto -> Warning
             warningCount++;
             details.scoreCapReason = 'suspicious_content';
        }
    }

    // NUOVA REGOLA: Fake RE:
    // Se l'oggetto inizia con RE: ma non è una risposta tecnica (In-Reply-To mancante) e non è in un thread, è sospetto.
    if (subject && /^\s*re:/i.test(subject) && !isReply && (!messageCount || messageCount <= 1)) {
        dangerCount++;
        details.scoreCapReason = 'fake_re_subject';
        details.fakeRe = true;
    }

    // NUOVA REGOLA: Richiesta Dati Sensibili
    if (sensitiveData && sensitiveData.length > 0) {
        details.sensitiveData = sensitiveData;
        
        // Se chiede dati sensibili, è già un warning forte.
        // Se INOLTRE chiede di inviarli a una mail esterna (diversa dal sender), è DANGER.
        let hasCrossDomainEmail = false;
        
        if (bodyEmails && bodyEmails.length > 0 && senderDomain) {
            const cleanSender = senderDomain.toLowerCase();
            hasCrossDomainEmail = bodyEmails.some(email => {
                const parts = email.split('@');
                if (parts.length < 2) return false;
                const domain = parts[1].toLowerCase();
                // Verifica se il dominio è diverso e non è parente
                return domain !== cleanSender && 
                       !domain.endsWith('.' + cleanSender) && 
                       !cleanSender.endsWith('.' + domain);
            });
        }
        
        if (hasCrossDomainEmail) {
            // Combinazione critica: chiede dati + invio esterno -> DANGER
            dangerCount++;
            details.scoreCapReason = 'sensitive_data_cross_domain';
            details.crossDomainEmails = true;
        } else {
            // Solo richiesta dati (es. "cambia la tua password") -> WARNING
            warningCount++;
            details.scoreCapReason = 'sensitive_data_request';
        }
    }

    // Applica i limiti basati su Warning e Danger
    if (dangerCount > 0) {
        // Logica cumulativa per i Danger
        if (dangerCount >= 3) {
            // Se ci sono 3 o più Danger, è sicuramente malevolo -> Max 1
            finalScore = Math.min(finalScore, 1);
        } else if (dangerCount === 2) {
            // Se ci sono 2 Danger, è molto sospetto -> Max 2
            finalScore = Math.min(finalScore, 2);
        } else {
            // Se c'è 1 solo Danger, è sospetto -> Max 3
            finalScore = Math.min(finalScore, 3);
        }
    } else if (warningCount > 0) {
        // Se c'è almeno un Warning (e nessun Danger), il punteggio massimo è 4
        // Se ci sono molti warning (>2), scendiamo a 3
        if (warningCount > 2) {
             finalScore = Math.min(finalScore, 3);
        } else {
             finalScore = Math.min(finalScore, 4);
        }
    }

    // REGOLA SPECIALE PROVIDER GENERICO:
    // Se è un provider generico (gmail, yahoo, etc.) e non ci sono altri warning/danger,
    // il punteggio massimo è comunque 4, perché non possiamo garantire l'identità al 100% (chiunque può creare un gmail).
    if (providerRisk === 'generic' && finalScore === 5) {
        finalScore = 4;
        warningCount++; // Lo contiamo come motivo di declassamento
    }

    finalScore = Math.max(1, Math.min(5, finalScore));

    details.totalPenalty = totalPenalty;
    details.normalizedPenalty = Math.round(normalizedPenalty * 100);
    details.warningCount = warningCount;
    details.dangerCount = dangerCount;

    return {
      score: finalScore,
      details,
    };
  }

  // ================================================================
  // Helpers
  // ================================================================

  _scoreAuth(value) {
    switch ((value || 'none').toLowerCase()) {
      case 'pass': return 1.0;
      case 'neutral': return 0.5;
      case 'softfail': return 0.3;
      case 'fail': return 0.0;
      case 'none': return 0.4;
      case 'temperror':
      case 'permerror': return 0.1;
      default: return 0.4;
    }
  }

  _authLabel(value) {
    switch ((value || 'none').toLowerCase()) {
      case 'pass': return 'pass';
      case 'neutral': return 'neutral';
      case 'softfail': return 'softfail';
      case 'fail': return 'fail';
      case 'none': return 'none';
      default: return value || 'none';
    }
  }

  _extractDomain(url) {
    try {
      if (!url) return null;
      
      if (url.startsWith('mailto:')) {
          // Rimuove mailto: e query params
          const emailPart = url.replace(/^mailto:/, '').split('?')[0];
          const parts = emailPart.split('@');
          return parts.length > 1 ? parts[1].toLowerCase() : null;
      }

      const parsed = new URL(url);
      return parsed.hostname.toLowerCase();
    } catch (e) {
      return null;
    }
  }

  _extractEmailDomain(emailStr) {
    if (!emailStr) return null;
    // Cerca pattern <email@domain> o email@domain
    const match = emailStr.match(/<([^>]+)>/) || emailStr.match(/([^\s]+@[^\s]+)/);
    if (match) {
        const email = match[1];
        const parts = email.split('@');
        return parts.length > 1 ? parts[1].trim().toLowerCase() : null;
    }
    return null;
  }

  _isGenericProvider(domain) {
      if (!domain) return false;
      const genericProviders = [
          'gmail.com', 'googlemail.com', 'yahoo.com', 'ymail.com', 
          'hotmail.com', 'outlook.com', 'live.com', 'msn.com', 
          'aol.com', 'icloud.com', 'me.com', 'mac.com', 
          'gmx.com', 'mail.com', 'libero.it', 'virgilio.it', 
          'tiscali.it', 'alice.it', 'tim.it', 'fastwebnet.it'
      ];
      return genericProviders.some(p => domain === p || domain.endsWith('.' + p));
  }

  _isHighRiskProvider(domain) {
      if (!domain) return false;
      const highRiskProviders = [
          'proton.me', 'protonmail.com', 'protonmail.ch',
          'tutanota.com', 'tuta.io', 'tuta.com',
          'guerrillamail.com', 'sharklasers.com', 
          'yopmail.com', 'temp-mail.org', '10minutemail.com',
          'mailinator.com', 'dispostable.com', 'trashmail.com'
      ];
      return highRiskProviders.some(p => domain === p || domain.endsWith('.' + p));
  }

  _hasSuspiciousCharacters(text) {
    if (!text) return false;
    
    // Regex per rilevare caratteri non latini (Cyrillic, Greek, etc.) che spesso
    // vengono usati per homograph attacks.
    // Range comuni:
    // Cyrillic: \u0400-\u04FF
    // Greek: \u0370-\u03FF
    // Armenian: \u0530-\u058F
    // Hebrew: \u0590-\u05FF
    // Arabic: \u0600-\u06FF
    // Syriac: \u0700-\u074F
    // Thaana: \u0780-\u07BF
    // Devanagari: \u0900-\u097F
    
    // Controlliamo se ci sono caratteri fuori dal range ASCII standard e Latin-1 Supplement
    // che sono spesso usati per spoofing.
    // Accettiamo lettere latine base, numeri, punti, trattini, underscore.
    
    // Se contiene caratteri Cirillici (spesso usati per spoofing visivo di a, e, o, p, c, x, y)
    const cyrillicPattern = /[\u0400-\u04FF]/;
    
    // Se contiene caratteri che sembrano latini ma non lo sono (es. Greek Omicron, Rho, etc.)
    const greekPattern = /[\u0370-\u03FF]/;
    
    // Un controllo più generico per "non standard domain chars" se vogliamo essere aggressivi:
    // Domini internazionali (IDN) legittimi iniziano con xn-- in ASCII.
    // Se vediamo caratteri unicode grezzi nel dominio estratto (che non è stato punycodato), è sospetto
    // in un contesto di visualizzazione se mescolati a latini.
    
    // Mixed script detection (molto semplificato):
    // Se contiene SIA caratteri latini CHE caratteri di altri script, è quasi sicuramente phishing.
    const latinPattern = /[a-zA-Z]/;
    
    if (cyrillicPattern.test(text) && latinPattern.test(text)) return true;
    if (greekPattern.test(text) && latinPattern.test(text)) return true;
    
    // Per ora blocchiamo in modo aggressivo qualsiasi uso di Cirillico nei domini
    // perché è il vettore n.1 di attacchi omografi.
    if (cyrillicPattern.test(text)) return true;

    return false;
  }
}
