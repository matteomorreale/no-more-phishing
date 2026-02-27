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
    } = params;

    const details = {};
    let totalPenalty = 0;

    // ================================================================
    // 1. SPF (peso: 20 punti di penalità massima)
    // ================================================================
    const spfScore = this._scoreAuth(spf);
    details.spf = { value: spf, score: spfScore, label: this._authLabel(spf) };
    totalPenalty += (1 - spfScore) * 20;

    // ================================================================
    // 2. DKIM (peso: 25 punti di penalità massima)
    // ================================================================
    const dkimScore = this._scoreAuth(dkim);
    details.dkim = { value: dkim, score: dkimScore, label: this._authLabel(dkim) };
    totalPenalty += (1 - dkimScore) * 25;

    // ================================================================
    // 3. DMARC (peso: 15 punti di penalità massima)
    // ================================================================
    const dmarcScore = this._scoreAuth(dmarc);
    details.dmarc = { value: dmarc, score: dmarcScore, label: this._authLabel(dmarc) };
    totalPenalty += (1 - dmarcScore) * 15;

    // ================================================================
    // 4. Corrispondenza dominio mittente (peso: 15 punti)
    // ================================================================
    if (senderDomainMatch === false) {
      details.senderDomainMatch = { match: false, penalty: 15 };
      totalPenalty += 15;
    } else {
      details.senderDomainMatch = { match: senderDomainMatch, penalty: 0 };
    }

    // ================================================================
    // 5. Reputazione dominio (peso: 20 punti)
    // ================================================================
    if (domainAnalysis?.isBlacklisted) {
      details.domain = { reputation: 'blacklisted', penalty: 20 };
      totalPenalty += 20;
    } else if (domainAnalysis?.reputation === 'suspicious') {
      details.domain = { reputation: 'suspicious', penalty: 10 };
      totalPenalty += 10;
    } else {
      details.domain = { reputation: domainAnalysis?.reputation || 'unknown', penalty: 0 };
    }

    // ================================================================
    // 6. URL malevoli (peso: 30 punti)
    // ================================================================
    const maliciousUrls = urlAnalysis?.results?.filter(r => r.isMalicious) || [];
    const urlPenalty = Math.min(maliciousUrls.length * 10, 30);
    details.urls = {
      total: urlAnalysis?.results?.length || 0,
      malicious: maliciousUrls.length,
      penalty: urlPenalty,
    };
    totalPenalty += urlPenalty;

    // ================================================================
    // 7. Parole chiave di urgenza/phishing (peso: 10 punti)
    // ================================================================
    const urgencyPenalty = Math.min(urgencyKeywords?.length * 2, 10);
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
    } else {
      details.attachments = { present: false, penalty: 0 };
    }

    // ================================================================
    // Calcolo score finale (da 1 a 5)
    // La penalità massima teorica è 140 punti.
    // Normalizziamo su 100 e mappiamo su scala 1-5.
    // ================================================================
    const maxPenalty = 140;
    const normalizedPenalty = Math.min(totalPenalty / maxPenalty, 1);
    // Score grezzo: 5 = nessuna penalità, 1 = penalità massima
    const rawScore = 5 - (normalizedPenalty * 4);
    const finalScore = Math.max(1, Math.min(5, Math.round(rawScore)));

    details.totalPenalty = totalPenalty;
    details.normalizedPenalty = Math.round(normalizedPenalty * 100);

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
}
