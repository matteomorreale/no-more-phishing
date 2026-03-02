/**
 * No More Phishing - Content Script
 * @author Matteo Morreale
 * @version 1.0.0
 *
 * Si integra con l'interfaccia di Gmail per rilevare l'apertura
 * di email e thread, richiedere l'analisi al service worker
 * e mostrare il risultato nell'overlay.
 */

(function () {
  'use strict';

  // ===================================================================
  // Stato interno
  // ===================================================================

  const NMP = {
    currentMessageId: null,
    currentThreadId: null,
    isAnalyzing: false,
    observer: null,
    overlayContainer: null,
  };

  // ===================================================================
  // Inizializzazione
  // ===================================================================

  function init() {
    // Attende che Gmail sia completamente caricato
    waitForGmail(() => {
      setupMutationObserver();
      checkCurrentEmail();
    });
  }

  function waitForGmail(callback) {
    const check = () => {
      if (document.querySelector('[data-message-id]') || document.querySelector('.nH')) {
        callback();
      } else {
        setTimeout(check, 500);
      }
    };
    check();
  }

  // ===================================================================
  // Observer per rilevare apertura email/thread
  // ===================================================================

  function setupMutationObserver() {
    NMP.observer = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        if (mutation.type === 'childList' || mutation.type === 'attributes') {
          checkCurrentEmail();
          break;
        }
      }
    });

    // Osserva il container principale di Gmail
    const mainContent = document.querySelector('.AO') || document.querySelector('[role="main"]') || document.body;
    NMP.observer.observe(mainContent, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ['data-message-id', 'data-thread-id'],
    });
  }

  // ===================================================================
  // Rilevamento email/thread corrente
  // ===================================================================

  function checkCurrentEmail() {
    // 1. Validazione URL: Assicurati di essere in una vista di dettaglio email
    // Pattern tipici: #inbox/ID, #sent/ID, #label/nome/ID, #all/ID
    // Se siamo solo su #inbox, #sent, ecc., non fare nulla.
    const hash = window.location.hash;
    const isListView = /^#(inbox|sent|starred|drafts|imp|trash|all|spam|label\/[^/]+)$/.test(hash);
    
    if (isListView || !hash) {
      console.log('[NMP] List view detected, hiding overlay');
      hideOverlay();
      return;
    }

    // 2. Cerca l'ID del thread dall'URL (Fonte più affidabile)
    // Aggiornato regex per supportare ID alfanumerici (come FMfcgz...) e non solo esadecimali
    const threadMatch = hash.match(/#(?:inbox|sent|starred|drafts|imp|trash|all|spam|label\/[^/]+)\/([a-zA-Z0-9_-]+)/i)
      || window.location.search.match(/[?&]th=([a-zA-Z0-9_-]+)/i);

    // 3. Cerca l'ID del messaggio nel DOM (solo se siamo in vista dettaglio)
    // Verifica presenza di elementi tipici della vista dettaglio (es. oggetto email .hP)
    const isDetailView = document.querySelector('.hP') !== null || document.querySelector('.ha') !== null;
    
    if (!isDetailView && !threadMatch) {
        hideOverlay();
        return;
    }

    const messageEl = document.querySelector('[data-message-id]');
    const messageId = messageEl ? messageEl.getAttribute('data-message-id') : null;
    
    // IMPORTANTE: L'ID nell'URL (es. FMfcgz...) è spesso un "internal ID" che non funziona con le API pubbliche.
    // Dobbiamo cercare il "data-legacy-thread-id" nel DOM, che è l'ID esadecimale corretto.
    let threadId = null;

    // Cerca ID legacy (hex)
    // Cerchiamo in più punti perché Gmail cambia spesso struttura
    // PRIORITY: H2 with class hP (Subject line) is the most reliable source
    const legacyThreadEl = document.querySelector('h2.hP[data-legacy-thread-id]') 
      || document.querySelector('h2[data-legacy-thread-id]')
      || document.querySelector('[data-legacy-thread-id]');
    
    if (legacyThreadEl) {
        threadId = legacyThreadEl.getAttribute('data-legacy-thread-id');
        console.log('[NMP] Found legacy thread ID from DOM:', threadId, 'Element:', legacyThreadEl.tagName, legacyThreadEl.className);
    } else {
        // TENTATIVO EXTRA: Cerca data-thread-perm-id (es. thread-f:1857010380590427128)
        const permThreadEl = document.querySelector('[data-thread-perm-id]');
        if (permThreadEl) {
             const permId = permThreadEl.getAttribute('data-thread-perm-id');
             console.log('[NMP] Found perm thread ID:', permId);
             if (permId && permId.startsWith('thread-f:')) {
                 // Convertiamo il decimale in hex
                 const decimalId = permId.replace('thread-f:', '');
                 try {
                     threadId = BigInt(decimalId).toString(16);
                     console.log('[NMP] Converted perm ID to hex:', threadId);
                 } catch (e) {
                     console.error('[NMP] Error converting perm ID:', e);
                 }
             }
        }

        if (!threadId) {
             // TENTATIVO ESTREMO: Cerca l'ID nel testo HTML o attributi span nascosti
             // Spesso Gmail mette l'ID in attributi come 'data-item-id' dentro le liste
             const itemEl = document.querySelector('div[role="main"] table tr[class*="zA"]');
             // Ma questo è per la lista... noi siamo nel dettaglio.
             
             // Nel dettaglio, a volte è in span.afn
             const spanId = document.querySelector('span[data-legacy-thread-id]');
             if (spanId) {
                  threadId = spanId.getAttribute('data-legacy-thread-id');
                  console.log('[NMP] Found legacy thread ID from span:', threadId);
             }
        }
    }

    // Se non troviamo il legacy ID, usiamo quello dell'URL come fallback (ma potrebbe fallire)
    if (!threadId && threadMatch) {
        // Se siamo in detail view ma non abbiamo trovato l'ID nel DOM, è probabile che il DOM non sia ancora pronto.
        // Invece di usare l'ID dell'URL che potrebbe essere sbagliato (es. 404), aspettiamo e riproviamo.
        if (isDetailView) {
             console.log('[NMP] In detail view but legacy ID missing. Retrying in 500ms...');
             setTimeout(checkCurrentEmail, 500);
             return;
        }

        threadId = threadMatch[1];
        console.warn('[NMP] Legacy ID not found in DOM. Using URL ID (unreliable):', threadId);

        // Se l'ID inizia con FM, è sicuramente un ID interno non valido per le API.
        // In questo caso, proviamo a ritardare l'analisi sperando che il DOM si carichi meglio.
        if (threadId.startsWith('FM')) {
             console.log('[NMP] Detected internal ID (FM...), waiting for DOM...');
             setTimeout(checkCurrentEmail, 1000); // Riprova tra 1 secondo
             return;
        }
    }

    // Fallback DOM standard
    if (!threadId && isDetailView) {
        const threadEl = document.querySelector('[data-thread-id]');
        const domThreadId = threadEl ? threadEl.getAttribute('data-thread-id') : null;
        if (domThreadId && domThreadId.length > 5) {
            threadId = domThreadId;
        }
    }

    // FIX: Se il threadId non è esadecimale (o contiene 'thread-f:'), significa che abbiamo fallito l'estrazione pulita
    // L'API di Gmail vuole solo esadecimale puro. Se abbiamo ancora 'thread-f:...' o simile, puliamo.
    if (threadId && threadId.toString().startsWith('thread-f:')) {
         const decimalId = threadId.replace('thread-f:', '');
         try {
             threadId = BigInt(decimalId).toString(16);
             console.log('[NMP] Late conversion of thread-f ID to hex:', threadId);
         } catch(e) {
             console.error('[NMP] Failed late conversion:', e);
         }
    }
    
    // Se l'ID è puramente numerico (decimale), convertiamolo in hex (es. ID vecchi)
    if (threadId && /^\d+$/.test(threadId)) {
        try {
             threadId = BigInt(threadId).toString(16);
             console.log('[NMP] Converted pure decimal ID to hex:', threadId);
        } catch(e) {
             console.error('[NMP] Failed decimal conversion:', e);
        }
    }

    const effectiveThreadId = threadId;
    const effectiveMessageId = messageId;
    
    console.log('[NMP] Detected view:', { 
        hash, 
        isListView, 
        isDetailView, 
        threadId: effectiveThreadId, 
        messageId: effectiveMessageId 
    });

    // Evita di ri-analizzare la stessa email
    if (
      effectiveThreadId === NMP.currentThreadId &&
      effectiveMessageId === NMP.currentMessageId
    ) {
      return;
    }

    if (!effectiveThreadId && !effectiveMessageId) {
      hideOverlay();
      return;
    }

    NMP.currentThreadId = effectiveThreadId;
    NMP.currentMessageId = effectiveMessageId;

    // Avvia l'analisi
    startAnalysis(effectiveMessageId, effectiveThreadId);
  }

  // ===================================================================
  // Avvio analisi
  // ===================================================================

  function startAnalysis(messageId, threadId) {
    if (NMP.isAnalyzing) return;
    if (!messageId && !threadId) return;

    NMP.isAnalyzing = true;
    showOverlayLoading();

    chrome.runtime.sendMessage(
      {
        type: 'ANALYZE_EMAIL',
        payload: { messageId, threadId },
      },
      (response) => {
        NMP.isAnalyzing = false;

        if (chrome.runtime.lastError) {
          console.error('[NMP] Errore comunicazione service worker:', chrome.runtime.lastError);
          showOverlayError(chrome.runtime.lastError.message);
          return;
        }

        if (!response) {
          showOverlayError('no_response');
          return;
        }

        if (response.success) {
          showOverlayResult(response.data);
        } else if (response.error === 'NOT_AUTHENTICATED') {
          showOverlayAuth();
        } else {
          showOverlayError(response.error);
        }
      }
    );
  }

  // ===================================================================
  // Gestione Overlay UI
  // ===================================================================

  function getOrCreateOverlay() {
    if (NMP.overlayContainer && document.contains(NMP.overlayContainer)) {
      return NMP.overlayContainer;
    }

    const container = document.createElement('div');
    container.id = 'nmp-overlay';
    container.className = 'nmp-overlay';

    // Cerca il miglior punto di inserimento in Gmail
    const insertionPoints = [
      '.ha',           // Header area email
      '.hP',           // Subject area
      '.adn',          // Email header
      '[role="main"]', // Main content
    ];

    let inserted = false;
    for (const selector of insertionPoints) {
      const target = document.querySelector(selector);
      if (target) {
        target.insertAdjacentElement('afterbegin', container);
        inserted = true;
        break;
      }
    }

    if (!inserted) {
      document.body.appendChild(container);
    }

    NMP.overlayContainer = container;
    return container;
  }

  function hideOverlay() {
    if (NMP.overlayContainer) {
      NMP.overlayContainer.style.display = 'none';
    }
  }

  function showOverlayLoading() {
    const overlay = getOrCreateOverlay();
    overlay.style.display = 'flex';
    overlay.innerHTML = `
      <div class="nmp-card nmp-loading">
        <div class="nmp-spinner"></div>
        <span class="nmp-loading-text">${getI18n('analyzing')}</span>
      </div>
    `;
  }

  function showOverlayAuth() {
    const overlay = getOrCreateOverlay();
    overlay.style.display = 'flex';
    overlay.innerHTML = `
      <div class="nmp-card nmp-auth">
        <div class="nmp-auth-icon">🔐</div>
        <div class="nmp-auth-text">${getI18n('authRequired')}</div>
        <button class="nmp-btn nmp-btn-primary" id="nmp-signin-btn">
          ${getI18n('signIn')}
        </button>
      </div>
    `;

    document.getElementById('nmp-signin-btn')?.addEventListener('click', () => {
      chrome.runtime.sendMessage({ type: 'SIGN_IN' }, (response) => {
        if (response?.success) {
          NMP.currentThreadId = null;
          NMP.currentMessageId = null;
          checkCurrentEmail();
        }
      });
    });
  }

  function showOverlayError(errorMsg) {
    const overlay = getOrCreateOverlay();
    overlay.style.display = 'flex';
    overlay.innerHTML = `
      <div class="nmp-card nmp-error">
        <div class="nmp-error-icon">⚠️</div>
        <div class="nmp-error-text">${getI18n('analysisError')}</div>
        <button class="nmp-btn nmp-btn-secondary" id="nmp-retry-btn">
          ${getI18n('retry')}
        </button>
      </div>
    `;

    document.getElementById('nmp-retry-btn')?.addEventListener('click', () => {
      NMP.currentThreadId = null;
      NMP.currentMessageId = null;
      checkCurrentEmail();
    });
  }

  function showOverlayResult(data) {
    console.log('[NMP] showOverlayResult called with:', data);
    const overlay = getOrCreateOverlay();
    const { score, details, emailData, urlAnalysis, domainAnalysis } = data;

    // A volte details è undefined o incompleto se c'è stato un errore parziale
    const safeDetails = details || {};
    const safeEmailData = emailData || {};
    const safeUrlAnalysis = urlAnalysis || { total: 0, malicious: 0, results: [] };
    const safeDomainAnalysis = domainAnalysis || { reputation: 'unknown' };

    const scoreClass = getScoreClass(score);
    const scoreLabel = getScoreLabel(score);
    const scoreIcon = getScoreIcon(score);

    overlay.style.display = 'flex';
    
    // Debug: log what we are about to render
    console.log('[NMP] Rendering details:', {
        spf: safeDetails.spf,
        urls: safeDetails.urls || safeUrlAnalysis, // Use correct source
        maliciousCount: safeUrlAnalysis.malicious || (safeDetails.urls ? safeDetails.urls.malicious : 0)
    });

    // FIX: Usa i dati corretti per i link. 
    // service-worker restituisce { urlAnalysis: { total, malicious, ... } }
    // ma qui a volte si usava details.urls
    const totalLinks = safeUrlAnalysis.total !== undefined ? safeUrlAnalysis.total : (safeDetails.urls?.total || 0);
    const maliciousLinks = safeUrlAnalysis.malicious !== undefined ? safeUrlAnalysis.malicious : (safeDetails.urls?.malicious || 0);

    // Determina se mostrare l'icona di warning
    // Mostra warning se ci sono parole chiave sospette, link mismatch o reply-to mismatch, o fake re, o sensitive data
    const hasWarning = safeDetails.urgency?.count > 0 || safeDetails.urls?.mismatch > 0 || !!safeDetails.replyToDomain || !!safeDetails.fakeRe || (safeDetails.sensitiveData && safeDetails.sensitiveData.length > 0);

    // Costruzione lista penalità
    const penalties = [];
    
    // Auth
    if (safeDetails.spf?.score < 1 || safeDetails.dkim?.score < 1 || safeDetails.dmarc?.score < 1) {
        penalties.push('Autenticazione mancante o debole (SPF/DKIM/DMARC)');
    }
    
    // Sender Domain
    if (safeDetails.senderDomainMatch?.match === false) {
        penalties.push("Il dominio del mittente non corrisponde all'intestazione From");
    }
    
    // Reply-To
    if (safeDetails.replyToDomain || safeDetails.scoreCapReason === 'reply_to_mismatch') {
        penalties.push("Indirizzo di risposta diverso dal mittente");
    }
    
    // Fake RE
    if (safeDetails.fakeRe || safeDetails.scoreCapReason === 'fake_re_subject') {
        penalties.push('Finto "RE:" nell\'oggetto');
    }
    
    // Scam Content
    if (safeDetails.scoreCapReason === 'scam_content_high_risk') {
        penalties.push('Contenuto tipico di truffa rilevato');
    }
    
    // Sensitive Data
    if (safeDetails.crossDomainEmails || safeDetails.scoreCapReason === 'sensitive_data_cross_domain') {
        penalties.push('Richiesta invio dati a dominio esterno');
    } else if (safeDetails.sensitiveData?.length > 0 || safeDetails.scoreCapReason === 'sensitive_data_request') {
        penalties.push('Richiesta di dati sensibili nel testo');
    }
    
    // Provider Risk
    if (safeDetails.domain?.providerRisk === 'generic') {
        penalties.push('Uso di provider email generico per comunicazioni business');
    } else if (safeDetails.domain?.providerRisk === 'high_risk') {
        penalties.push('Uso di provider email ad alto rischio/temporaneo');
    }
    
    // Domain Reputation
    if (safeDetails.domain?.reputation === 'suspicious' || safeDetails.domain?.isBlacklisted) {
        penalties.push('Dominio con reputazione sospetta o in blacklist');
    }
    if (safeDetails.domainSuspiciousChars) {
        penalties.push('Dominio mittente con caratteri sospetti');
    }
    
    // URLs
    if (safeDetails.urls?.mismatch > 0) {
        penalties.push('Link che puntano a domini diversi dal mittente');
    }
    if (safeDetails.urls?.suspiciousChars > 0) {
        penalties.push('Link con caratteri sospetti (omografi)');
    }
    
    // Urgency
    if (safeDetails.urgency?.count > 0) {
        penalties.push('Uso di parole chiave di urgenza/pressione');
    }
    
    // Attachments
    if (safeEmailData.hasAttachments) {
        penalties.push('Presenza di allegati potenzialmente rischiosi');
    }

    // Fallback
    if (penalties.length === 0 && (safeDetails.warningCount > 0 || safeDetails.dangerCount > 0 || safeDetails.totalPenalty > 0)) {
        if (safeDetails.totalPenalty > 0 && safeDetails.warningCount === 0 && safeDetails.dangerCount === 0) {
             penalties.push('Accumulo di penalità minori (es. reputazione, link)');
        } else {
             penalties.push('Fattori di rischio multipli non specifici');
        }
    }

    overlay.innerHTML = `
      <div class="nmp-card nmp-result nmp-score-${score}">
        
        <!-- Header con score -->
        <div class="nmp-result-header">
          <div class="nmp-score-badge nmp-${scoreClass}">
            <span class="nmp-score-icon">${scoreIcon}</span>
            <span class="nmp-score-number">${score}</span>
            <span class="nmp-score-max">/5</span>
            ${hasWarning ? `<div class="nmp-score-warning" title="${getI18n('warningHint')}">⚠️</div>` : ''}
          </div>
          <div class="nmp-score-info">
            <div class="nmp-score-label-row">
              <span class="nmp-score-label">${scoreLabel}</span>
              <span class="nmp-sender-address-large">${escapeHtml(safeEmailData.fromEmail || safeEmailData.senderDomain || '').toUpperCase()}</span>
            </div>
            <div class="nmp-sender-info">
              ${safeEmailData.isThread ? `<span class="nmp-thread-badge">${getI18n('thread')} (${safeEmailData.messageCount})</span>` : ''}
            </div>
          </div>
          <button class="nmp-toggle-btn" id="nmp-toggle-details" title="${getI18n('showDetails')}">
            <svg viewBox="0 0 24 24" width="16" height="16"><path d="M7 10l5 5 5-5z" fill="currentColor"/></svg>
          </button>
        </div>

        <!-- Barra score visiva -->
        <div class="nmp-score-bar-container">
          <div class="nmp-score-bar">
            <div class="nmp-score-fill nmp-${scoreClass}" style="width: ${(score / 5) * 100}%"></div>
          </div>
          <div class="nmp-score-ticks">
            ${[1,2,3,4,5].map(i => `<span class="${i <= score ? 'active' : ''}"></span>`).join('')}
          </div>
        </div>

        <!-- Penalties Section (Mostra solo se ci sono penalità che riducono il punteggio) -->
        ${penalties.length > 0 ? `
        <div class="nmp-penalties-section" style="margin-top: 8px; padding: 8px; background: rgba(0,0,0,0.05); border-radius: 4px;">
            <div class="nmp-section-title" style="color: #d93025; font-weight: bold;">⚠️ Motivi della penalizzazione:</div>
            <ul style="margin: 4px 0 0 16px; padding: 0; font-size: 11px; color: #444;">
                ${penalties.map(p => `<li>${p}</li>`).join('')}
            </ul>
        </div>
        ` : ''}

        <!-- Dettagli (collassabili) -->
        <div class="nmp-details" id="nmp-details-panel" style="display:none;">
          
          <!-- Autenticazione Email -->
          <div class="nmp-section">
            <div class="nmp-section-title">${getI18n('emailAuthentication')}</div>
            <div class="nmp-auth-grid">
              ${renderAuthBadge('SPF', safeDetails.spf?.label || safeDetails.spf?.status)}
              ${renderAuthBadge('DKIM', safeDetails.dkim?.label || safeDetails.dkim?.status)}
              ${renderAuthBadge('DMARC', safeDetails.dmarc?.label || safeDetails.dmarc?.status)}
            </div>
          </div>

          <!-- Mittente -->
          <div class="nmp-section">
            <div class="nmp-section-title">${getI18n('sender')}</div>
            <div class="nmp-detail-row">
              <span class="nmp-detail-label">${getI18n('domain')}</span>
              <span class="nmp-detail-value">${escapeHtml(safeEmailData.senderDomain || 'N/A')}</span>
            </div>
            <div class="nmp-detail-row">
              <span class="nmp-detail-label">${getI18n('domainMatch')}</span>
              <span class="nmp-detail-value ${safeDetails.senderDomainMatch?.match === false ? 'nmp-danger' : 'nmp-ok'}">
                ${safeDetails.senderDomainMatch?.match === false ? '✗ ' + getI18n('mismatch') : safeDetails.senderDomainMatch?.match === true ? '✓ ' + getI18n('match') : getI18n('unknown')}
              </span>
            </div>
            <div class="nmp-detail-row">
              <span class="nmp-detail-label">${getI18n('reputation')}</span>
              <span class="nmp-detail-value ${getDomainReputationClass(safeDomainAnalysis?.reputation)}">
                ${getDomainReputationLabel(safeDomainAnalysis?.reputation)}
              </span>
            </div>
            ${safeDetails.replyToDomain ? `
            <div class="nmp-detail-row">
              <span class="nmp-detail-label nmp-danger-text">${getI18n('replyToMismatch')}</span>
              <span class="nmp-detail-value nmp-danger">${escapeHtml(safeDetails.replyToDomain)}</span>
            </div>
            ` : ''}
            ${safeDetails.fakeRe ? `
            <div class="nmp-detail-row">
              <span class="nmp-detail-label nmp-danger-text">${getI18n('fakeReWarning')}</span>
              <span class="nmp-detail-value nmp-danger">⚠️</span>
            </div>
            ` : ''}
            ${safeDetails.sensitiveData && safeDetails.sensitiveData.length > 0 ? `
            <div class="nmp-detail-row" style="flex-direction:column; align-items:flex-start; gap:8px;">
              <span class="nmp-detail-label nmp-warning-text">${getI18n('sensitiveDataWarning')}</span>
              <div class="nmp-keywords">
                ${safeDetails.sensitiveData.map(kw => `<span class="nmp-keyword">${escapeHtml(kw)}</span>`).join('')}
              </div>
            </div>
            ` : ''}
            ${safeDetails.crossDomainEmails ? `
            <div class="nmp-detail-row">
              <span class="nmp-detail-label nmp-danger-text">${getI18n('crossDomainWarning')}</span>
              <span class="nmp-detail-value nmp-danger">⚠️</span>
            </div>
            ` : ''}
            ${safeDetails.domain?.providerRisk === 'generic' ? `
            <div class="nmp-detail-row">
              <span class="nmp-detail-label">${getI18n('provider')}</span>
              <span class="nmp-detail-value nmp-warning">${getI18n('genericProvider')}</span>
            </div>
            ` : ''}
            ${safeDetails.domain?.providerRisk === 'high_risk' ? `
            <div class="nmp-detail-row">
              <span class="nmp-detail-label">${getI18n('provider')}</span>
              <span class="nmp-detail-value nmp-danger">${getI18n('highRiskProvider')}</span>
            </div>
            ` : ''}
          </div>

          <!-- Link analizzati -->
          <div class="nmp-section">
            <div class="nmp-section-title">${getI18n('links')}</div>
            <div class="nmp-detail-row">
              <span class="nmp-detail-label">${getI18n('totalLinks')}</span>
              <span class="nmp-detail-value">${totalLinks}</span>
            </div>
            <div class="nmp-detail-row">
              <span class="nmp-detail-label">${getI18n('maliciousLinks')}</span>
              <span class="nmp-detail-value ${maliciousLinks > 0 ? 'nmp-danger' : 'nmp-ok'}">
                ${maliciousLinks}
              </span>
            </div>
            ${safeDetails.urls?.mismatch > 0 ? `
            <div class="nmp-detail-row">
              <span class="nmp-detail-label">${getI18n('mismatchedLinks')}</span>
              <span class="nmp-detail-value nmp-warning">
                ${safeDetails.urls.mismatch}
              </span>
            </div>
            ` : ''}
             ${maliciousLinks > 0 ? `
            <div class="nmp-malicious-list">
                ${(safeUrlAnalysis.results || []).filter(u => u.isMalicious).map(u => `<div class="nmp-malicious-url">${escapeHtml(u.url)}</div>`).join('')}
            </div>
            ` : ''}
          </div>

          <!-- Parole chiave sospette -->
          ${safeDetails.urgency?.count > 0 ? `
          <div class="nmp-section">
            <div class="nmp-section-title">${getI18n('urgencyKeywords')}</div>
            <div class="nmp-keywords">
              ${safeDetails.urgency.keywords.map(kw => `<span class="nmp-keyword">${formatKeyword(kw)}</span>`).join('')}
            </div>
          </div>
          ` : ''}

          <!-- Allegati -->
          ${safeEmailData.hasAttachments ? `
          <div class="nmp-section nmp-warning-section">
            <span class="nmp-warning-icon">📎</span>
            <span>${getI18n('hasAttachments')}</span>
          </div>
          ` : ''}

        </div>

        <!-- Footer -->
        <div class="nmp-footer">
          <span class="nmp-brand">No More Phishing</span>
          <button class="nmp-close-btn" id="nmp-close-btn" title="${getI18n('close')}">×</button>
        </div>
      </div>
    `;

    // Toggle dettagli
    document.getElementById('nmp-toggle-details')?.addEventListener('click', () => {
      const panel = document.getElementById('nmp-details-panel');
      const btn = document.getElementById('nmp-toggle-details');
      if (panel) {
        const isHidden = panel.style.display === 'none';
        panel.style.display = isHidden ? 'block' : 'none';
        btn.classList.toggle('nmp-rotated', isHidden);
      }
    });

    // Chiudi overlay
    document.getElementById('nmp-close-btn')?.addEventListener('click', () => {
      hideOverlay();
    });
  }

  // ===================================================================
  // Helper UI
  // ===================================================================

  function renderAuthBadge(name, status) {
    const cls = getAuthClass(status);
    return `
      <div class="nmp-auth-badge nmp-auth-${cls}">
        <span class="nmp-auth-name">${name}</span>
        <span class="nmp-auth-status">${(status || 'none').toUpperCase()}</span>
      </div>
    `;
  }

  function getAuthClass(status) {
    switch ((status || 'none').toLowerCase()) {
      case 'pass': return 'pass';
      case 'neutral': return 'neutral';
      case 'softfail': return 'softfail';
      case 'fail': return 'fail';
      default: return 'none';
    }
  }

  function getScoreClass(score) {
    if (score >= 5) return 'excellent';
    if (score >= 4) return 'good';
    if (score >= 3) return 'medium';
    if (score >= 2) return 'low';
    return 'critical';
  }

  function getScoreIcon(score) {
    if (score >= 5) return '✓';
    if (score >= 4) return '✓';
    if (score >= 3) return '~';
    if (score >= 2) return '!';
    return '✕';
  }

  function getScoreLabel(score) {
    const lang = navigator.language.startsWith('it') ? 'it' : 'en';
    const labels = {
      it: { 
        5: 'Molto Affidabile', 
        4: 'Discretamente Affidabile', 
        3: 'Incerto', 
        2: 'Sospetto', 
        1: 'Pericoloso' 
      },
      en: { 
        5: 'Very Trustworthy', 
        4: 'Fairly Trustworthy', 
        3: 'Uncertain', 
        2: 'Suspicious', 
        1: 'Dangerous' 
      },
    };
    return labels[lang][score] || labels.en[score];
  }

  function getDomainReputationClass(reputation) {
    switch (reputation) {
      case 'clean': return 'nmp-ok';
      case 'suspicious': return 'nmp-warning';
      case 'blacklisted': return 'nmp-danger';
      default: return '';
    }
  }

  function getDomainReputationLabel(reputation) {
    const lang = navigator.language.startsWith('it') ? 'it' : 'en';
    const labels = {
      it: { clean: 'Pulito', suspicious: 'Sospetto', blacklisted: 'Blacklistato', unknown: 'Sconosciuto' },
      en: { clean: 'Clean', suspicious: 'Suspicious', blacklisted: 'Blacklisted', unknown: 'Unknown' },
    };
    return (labels[lang][reputation] || labels.en.unknown);
  }

  function getI18n(key) {
    const lang = navigator.language.startsWith('it') ? 'it' : 'en';
    const strings = {
      it: {
        analyzing: 'Analisi in corso...',
        authRequired: 'Accedi con Google per analizzare le email',
        signIn: 'Accedi con Google',
        analysisError: 'Errore durante l\'analisi',
        retry: 'Riprova',
        showDetails: 'Mostra dettagli',
        emailAuthentication: 'Autenticazione Email',
        sender: 'Mittente',
        domain: 'Dominio',
        domainMatch: 'Corrispondenza dominio',
        match: 'Corrispondente',
        mismatch: 'Non corrispondente',
        reputation: 'Reputazione',
        provider: 'Provider Email',
        genericProvider: 'Generico (Attenzione)',
        highRiskProvider: 'Alto Rischio (Pericolo)',
        links: 'Link',
        totalLinks: 'Link totali',
        maliciousLinks: 'Link malevoli',
        mismatchedLinks: 'Link esterni al dominio',
        urgencyKeywords: 'Parole chiave sospette',
        hasAttachments: 'Email con allegati — verificare con attenzione',
        thread: 'Thread',
        unknown: 'Sconosciuto',
        close: 'Chiudi',
        warningHint: 'Elementi sospetti rilevati',
        suspiciousAmount: 'Importo monetario sospetto',
        replyToMismatch: 'Reply-To diverso dal mittente',
        replyToLabel: 'Rispondi a',
        fakeReWarning: 'Finto "RE:" rilevato (non è una risposta)',
        sensitiveDataWarning: 'Richiesta dati sensibili rilevata',
        crossDomainWarning: 'Richiesta invio dati a dominio esterno',
      },
      en: {
        analyzing: 'Analyzing...',
        authRequired: 'Sign in with Google to analyze emails',
        signIn: 'Sign in with Google',
        analysisError: 'Analysis error',
        retry: 'Retry',
        showDetails: 'Show details',
        emailAuthentication: 'Email Authentication',
        sender: 'Sender',
        domain: 'Domain',
        domainMatch: 'Domain match',
        match: 'Match',
        mismatch: 'Mismatch',
        reputation: 'Reputation',
        provider: 'Email Provider',
        genericProvider: 'Generic (Warning)',
        highRiskProvider: 'High Risk (Danger)',
        links: 'Links',
        totalLinks: 'Total links',
        maliciousLinks: 'Malicious links',
        mismatchedLinks: 'External domain links',
        urgencyKeywords: 'Suspicious keywords',
        hasAttachments: 'Attachments detected — verify carefully',
        thread: 'Thread',
        unknown: 'Unknown',
        close: 'Close',
        warningHint: 'Suspicious elements detected',
        suspiciousAmount: 'Suspicious monetary amount',
        replyToMismatch: 'Reply-To different from sender',
        fakeReWarning: 'Fake "RE:" detected (not a reply)',
        sensitiveDataWarning: 'Sensitive data request detected',
        crossDomainWarning: 'Request to send data to external domain',
        replyToLabel: 'Reply-To',
      },
    };
    return strings[lang][key] || strings.en[key] || key;
  }

  function formatKeyword(kw) {
    if (kw === 'suspicious_amount_detected') {
      return getI18n('suspiciousAmount');
    }
    return escapeHtml(kw);
  }

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
  }

  // ===================================================================
  // Avvio
  // ===================================================================

  init();

})();
