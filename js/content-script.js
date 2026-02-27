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
    // Cerca l'ID del thread dall'URL
    const threadMatch = window.location.hash.match(/#(?:inbox|sent|all|label\/[^/]+)\/([a-f0-9]+)/i)
      || window.location.search.match(/[?&]th=([a-f0-9]+)/i);

    // Cerca l'ID del messaggio nel DOM
    const messageEl = document.querySelector('[data-message-id]');
    const messageId = messageEl ? messageEl.getAttribute('data-message-id') : null;
    const threadId = threadMatch ? threadMatch[1] : null;

    // Cerca il thread ID anche nel DOM (Gmail lo espone in vari modi)
    const threadEl = document.querySelector('[data-thread-id]');
    const domThreadId = threadEl ? threadEl.getAttribute('data-thread-id') : null;

    const effectiveThreadId = domThreadId || threadId;
    const effectiveMessageId = messageId;

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
    const overlay = getOrCreateOverlay();
    const { score, details, emailData, urlAnalysis, domainAnalysis } = data;

    const scoreClass = getScoreClass(score);
    const scoreLabel = getScoreLabel(score);
    const scoreIcon = getScoreIcon(score);

    overlay.style.display = 'flex';
    overlay.innerHTML = `
      <div class="nmp-card nmp-result nmp-score-${score}">
        
        <!-- Header con score -->
        <div class="nmp-result-header">
          <div class="nmp-score-badge nmp-${scoreClass}">
            <span class="nmp-score-icon">${scoreIcon}</span>
            <span class="nmp-score-number">${score}</span>
            <span class="nmp-score-max">/5</span>
          </div>
          <div class="nmp-score-info">
            <div class="nmp-score-label">${scoreLabel}</div>
            <div class="nmp-sender-info">
              <span class="nmp-sender-domain">${escapeHtml(emailData.senderDomain || '')}</span>
              ${emailData.isThread ? `<span class="nmp-thread-badge">${getI18n('thread')} (${emailData.messageCount})</span>` : ''}
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

        <!-- Dettagli (collassabili) -->
        <div class="nmp-details" id="nmp-details-panel" style="display:none;">
          
          <!-- Autenticazione Email -->
          <div class="nmp-section">
            <div class="nmp-section-title">${getI18n('emailAuthentication')}</div>
            <div class="nmp-auth-grid">
              ${renderAuthBadge('SPF', details.spf?.label)}
              ${renderAuthBadge('DKIM', details.dkim?.label)}
              ${renderAuthBadge('DMARC', details.dmarc?.label)}
            </div>
          </div>

          <!-- Mittente -->
          <div class="nmp-section">
            <div class="nmp-section-title">${getI18n('sender')}</div>
            <div class="nmp-detail-row">
              <span class="nmp-detail-label">${getI18n('domain')}</span>
              <span class="nmp-detail-value">${escapeHtml(emailData.senderDomain || 'N/A')}</span>
            </div>
            <div class="nmp-detail-row">
              <span class="nmp-detail-label">${getI18n('domainMatch')}</span>
              <span class="nmp-detail-value ${details.senderDomainMatch?.match === false ? 'nmp-danger' : 'nmp-ok'}">
                ${details.senderDomainMatch?.match === false ? '✗ ' + getI18n('mismatch') : details.senderDomainMatch?.match === true ? '✓ ' + getI18n('match') : getI18n('unknown')}
              </span>
            </div>
            <div class="nmp-detail-row">
              <span class="nmp-detail-label">${getI18n('reputation')}</span>
              <span class="nmp-detail-value ${getDomainReputationClass(domainAnalysis?.reputation)}">
                ${getDomainReputationLabel(domainAnalysis?.reputation)}
              </span>
            </div>
          </div>

          <!-- Link analizzati -->
          <div class="nmp-section">
            <div class="nmp-section-title">${getI18n('links')}</div>
            <div class="nmp-detail-row">
              <span class="nmp-detail-label">${getI18n('totalLinks')}</span>
              <span class="nmp-detail-value">${details.urls?.total || 0}</span>
            </div>
            <div class="nmp-detail-row">
              <span class="nmp-detail-label">${getI18n('maliciousLinks')}</span>
              <span class="nmp-detail-value ${details.urls?.malicious > 0 ? 'nmp-danger' : 'nmp-ok'}">
                ${details.urls?.malicious || 0}
              </span>
            </div>
          </div>

          <!-- Parole chiave sospette -->
          ${details.urgency?.count > 0 ? `
          <div class="nmp-section">
            <div class="nmp-section-title">${getI18n('urgencyKeywords')}</div>
            <div class="nmp-keywords">
              ${details.urgency.keywords.map(kw => `<span class="nmp-keyword">${escapeHtml(kw)}</span>`).join('')}
            </div>
          </div>
          ` : ''}

          <!-- Allegati -->
          ${emailData.hasAttachments ? `
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
      it: { 5: 'Molto Affidabile', 4: 'Affidabile', 3: 'Incerto', 2: 'Sospetto', 1: 'Pericoloso' },
      en: { 5: 'Very Trustworthy', 4: 'Trustworthy', 3: 'Uncertain', 2: 'Suspicious', 1: 'Dangerous' },
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
        links: 'Link',
        totalLinks: 'Link totali',
        maliciousLinks: 'Link malevoli',
        urgencyKeywords: 'Parole chiave sospette',
        hasAttachments: 'Email con allegati — verificare con attenzione',
        thread: 'Thread',
        unknown: 'Sconosciuto',
        close: 'Chiudi',
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
        links: 'Links',
        totalLinks: 'Total links',
        maliciousLinks: 'Malicious links',
        urgencyKeywords: 'Suspicious keywords',
        hasAttachments: 'Email has attachments — verify carefully',
        thread: 'Thread',
        unknown: 'Unknown',
        close: 'Close',
      },
    };
    return strings[lang][key] || strings.en[key] || key;
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
