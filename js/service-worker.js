/**
 * No More Phishing - Service Worker (Background)
 * @author Matteo Morreale
 * @version 1.0.0
 *
 * Gestisce l'autenticazione OAuth, le chiamate alla Gmail API,
 * la comunicazione con il backend proxy e il calcolo dello score.
 */

import { GmailAnalyzer } from './gmail-analyzer.js';
import { ScoreCalculator } from './score-calculator.js';
import { ProxyClient } from './proxy-client.js';

// --- Configurazione ---
const CONFIG = {
  PROXY_BASE_URL: 'https://nomorephishing.matteomorreale.it/',
  GMAIL_API_BASE: 'https://www.googleapis.com/gmail/v1/users/me/',
  NOTIFICATION_THRESHOLD: 2, // Notifica se score <= 2
};

// --- Stato interno ---
let authToken = null;

// =====================================================================
// Gestione Messaggi dal Content Script
// =====================================================================

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'ANALYZE_EMAIL') {
    handleAnalyzeEmail(message.payload)
      .then(result => sendResponse({ success: true, data: result }))
      .catch(error => sendResponse({ success: false, error: error.message }));
    return true; // Mantieni il canale aperto per la risposta asincrona
  }

  if (message.type === 'GET_AUTH_STATUS') {
    getAuthToken(false)
      .then(token => sendResponse({ authenticated: !!token }))
      .catch(() => sendResponse({ authenticated: false }));
    return true;
  }

  if (message.type === 'SIGN_IN') {
    getAuthToken(true)
      .then(token => sendResponse({ success: !!token }))
      .catch(error => sendResponse({ success: false, error: error.message }));
    return true;
  }

  if (message.type === 'SIGN_OUT') {
    signOut()
      .then(() => sendResponse({ success: true }))
      .catch(error => sendResponse({ success: false, error: error.message }));
    return true;
  }
});

// =====================================================================
// Autenticazione OAuth 2.0
// =====================================================================

async function getAuthToken(interactive = false) {
  // 1. Controlla se abbiamo già un token in memoria (utile per il fallback flow)
  if (authToken) {
    return authToken;
  }

  // Controlla nello storage locale
  const stored = await chrome.storage.local.get('authToken');
  if (stored.authToken) {
    authToken = stored.authToken;
    return authToken;
  }

  // 2. Prova il metodo standard (Chrome Identity / Browser Profile)
  try {
    const token = await new Promise((resolve, reject) => {
      chrome.identity.getAuthToken({ interactive }, (token) => {
        if (chrome.runtime.lastError) {
          // Se non è interattivo, non lanciare errore subito, prova il fallback se necessario
          reject(new Error(chrome.runtime.lastError.message));
        } else {
          resolve(token);
        }
      });
    });
    authToken = token;
    await chrome.storage.local.set({ authToken: token });
    return token;
  } catch (error) {
    // 3. Fallback: Se l'utente ha disabilitato il login nel browser, usa WebAuthFlow
    // "The user turned off browser signin" è l'errore tipico.
    const isSignInDisabled = error.message && (
      error.message.includes('browser signin') || 
      error.message.includes('User is not signed in')
    );

    // Se stiamo già provando in modo interattivo, o se è un controllo in background che fallisce
    // ma sappiamo che dobbiamo usare il fallback
    if (interactive && isSignInDisabled) {
      console.warn('[NMP] Browser sign-in disabled, falling back to WebAuthFlow');
      try {
        const token = await launchWebAuthFlow();
        authToken = token;
        await chrome.storage.local.set({ authToken: token });
        return token;
      } catch (fallbackError) {
        throw new Error(fallbackError.message || 'Auth fallback failed');
      }
    }

    // Se non è interattivo o è un altro errore, ritorna null o lancia errore
    if (!interactive) {
      return null;
    }
    throw error;
  }
}

async function launchWebAuthFlow() {
  const manifest = chrome.runtime.getManifest();
  const clientId = manifest.oauth2.client_id;
  const scopes = manifest.oauth2.scopes.join(' ');
  const redirectUri = chrome.identity.getRedirectURL();
  
  console.log('[NMP] Using Client ID:', clientId);
  console.log('[NMP] Using Redirect URI:', redirectUri);

  const authUrl = new URL('https://accounts.google.com/o/oauth2/auth');
  authUrl.searchParams.set('client_id', clientId);
  authUrl.searchParams.set('response_type', 'token');
  authUrl.searchParams.set('redirect_uri', redirectUri);
  authUrl.searchParams.set('scope', scopes);

  return new Promise((resolve, reject) => {
    chrome.identity.launchWebAuthFlow(
      { url: authUrl.toString(), interactive: true },
      (redirectUrl) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }
        if (!redirectUrl) {
          reject(new Error('No redirect URL'));
          return;
        }
        
        // Estrai token dall'hash URL
        const params = new URLSearchParams(new URL(redirectUrl).hash.substring(1));
        const token = params.get('access_token');
        if (token) {
          resolve(token);
        } else {
          reject(new Error('No access token found'));
        }
      }
    );
  });
}

async function signOut() {
  if (authToken) {
    try {
      const url = `https://accounts.google.com/o/oauth2/revoke?token=${authToken}`;
      await fetch(url);
      
      // Clear token from Chrome Identity cache
      await new Promise((resolve) => {
        chrome.identity.removeCachedAuthToken({ token: authToken }, resolve);
      });
    } catch (e) {
      console.warn('Revoke failed', e);
    }
    authToken = null;
  }
  await chrome.storage.local.remove('authToken');
}

// =====================================================================
// Analisi Email Principale
// =====================================================================

async function handleAnalyzeEmail({ messageId, threadId }) {
  try {
    // 1. Ottieni token di autenticazione
    const token = await getAuthToken(false);
    if (!token) {
      throw new Error('NOT_AUTHENTICATED');
    }

    // 2. Recupera i dati dell'email (o del thread) dalla Gmail API
    console.log('[NMP] Analyzing email:', messageId, 'Thread:', threadId);
    let analyzer = new GmailAnalyzer(token, CONFIG.GMAIL_API_BASE);
    let emailData;

    try {
        if (threadId) {
            emailData = await analyzer.analyzeThread(threadId);
        } else {
            emailData = await analyzer.analyzeMessage(messageId);
        }
    } catch (apiError) {
        // GESTIONE TOKEN SCADUTO (401)
        // Se riceviamo un 401, proviamo a rimuovere il token dalla cache e richiederne uno nuovo
        if (apiError.message && apiError.message.includes('401')) {
            console.warn('[NMP] Token expired (401). Refreshing token...');
            
            // Rimuovi token dalla cache di Chrome
            await new Promise(resolve => {
                chrome.identity.removeCachedAuthToken({ token: token }, resolve);
            });
            
            // Rimuovi token dallo storage locale
            await chrome.storage.local.remove('authToken');
            authToken = null;

            // Richiedi nuovo token (senza interazione se possibile)
            const newToken = await getAuthToken(false);
            if (!newToken) {
                throw new Error('NOT_AUTHENTICATED_AFTER_REFRESH');
            }

            // Riprova la richiesta con il nuovo token
            console.log('[NMP] Retrying request with new token...');
            analyzer = new GmailAnalyzer(newToken, CONFIG.GMAIL_API_BASE);
            if (threadId) {
                emailData = await analyzer.analyzeThread(threadId);
            } else {
                emailData = await analyzer.analyzeMessage(messageId);
            }
        } else {
            throw apiError; // Rilancia altri errori
        }
    }
    
    console.log('[NMP] Email data retrieved:', emailData);

    // 3. Analizza URL con il backend proxy
    const data = await chrome.storage.local.get('settings');
    const settings = data.settings || {};
    let proxyUrl = settings.proxyUrl || CONFIG.PROXY_BASE_URL;
    
    // Se l'URL salvato è ancora il placeholder vecchio, usa quello nuovo
    if (proxyUrl.includes('YOUR_SERVER_DOMAIN')) {
      proxyUrl = CONFIG.PROXY_BASE_URL;
    }

    const proxyClient = new ProxyClient(proxyUrl);
    let urlAnalysis = { results: [], hasThreats: false };

    if (emailData.urls && emailData.urls.length > 0) {
      console.log('[NMP] Checking URLs:', emailData.urls);
      urlAnalysis = await proxyClient.checkUrls(emailData.urls);
      console.log('[NMP] URL Analysis result:', urlAnalysis);
    }

    // 4. Analizza il dominio del mittente
    let domainAnalysis = { reputation: 'unknown', isBlacklisted: false };
    if (emailData.senderDomain) {
      console.log('[NMP] Checking domain:', emailData.senderDomain);
      domainAnalysis = await proxyClient.checkDomain(emailData.senderDomain);
      console.log('[NMP] Domain Analysis result:', domainAnalysis);
    }

    // 5. Calcola lo score finale
    const calculator = new ScoreCalculator();
    const scoreResult = calculator.calculate({
      spf: emailData.spf,
      dkim: emailData.dkim,
      dmarc: emailData.dmarc,
      senderDomainMatch: emailData.senderDomainMatch,
      domainAnalysis,
      urlAnalysis, // Passiamo l'oggetto completo { total, malicious, results }
      urgencyKeywords: emailData.urgencyKeywords,
      hasAttachments: emailData.hasAttachments,
      isReply: emailData.isReply,
      senderDomain: emailData.senderDomain,
      replyTo: emailData.replyTo,
      urls: emailData.urls,
      subject: emailData.subject,
      messageCount: emailData.messageCount || 1,
      sensitiveData: emailData.sensitiveData,
      bodyEmails: emailData.bodyEmails,
    });

    // DEBUG: Log score result details
    console.log('[NMP] Score result:', scoreResult);

    // 6. Invia notifica se score basso
    if (scoreResult.score <= CONFIG.NOTIFICATION_THRESHOLD) {
      sendPhishingNotification(emailData.subject, scoreResult.score);
    }

    // 7. Restituisci il risultato completo
    // Assicuriamoci che 'details' contenga i dati corretti sugli URL
    // ScoreCalculator potrebbe non passare tutto l'oggetto urlAnalysis dentro details.urls
    
    // Merge dei dettagli URL calcolati e quelli dell'analisi proxy
    const calculatedUrls = scoreResult.details.urls || {};
    const proxyUrls = {
        total: urlAnalysis.total || (emailData.urls ? emailData.urls.length : 0),
        malicious: urlAnalysis.malicious || 0,
        hasThreats: urlAnalysis.hasThreats || false
    };

    return {
      score: scoreResult.score,
      details: {
        ...scoreResult.details,
        urls: {
            ...calculatedUrls,
            ...proxyUrls,
            // Preserviamo i campi calcolati che proxyUrls non ha
            mismatch: calculatedUrls.mismatch || 0,
            suspiciousChars: calculatedUrls.suspiciousChars || 0,
            penalty: calculatedUrls.penalty || 0
        }
      },
      emailData: {
        subject: emailData.subject,
        sender: emailData.sender,
        senderDomain: emailData.senderDomain,
        date: emailData.date,
        spf: emailData.spf,
        dkim: emailData.dkim,
        dmarc: emailData.dmarc,
        // urls: emailData.urls, // Rimuoviamo la lista grezza per alleggerire il messaggio
        hasAttachments: emailData.hasAttachments,
        isThread: !!threadId,
        messageCount: emailData.messageCount || 1,
      },
      urlAnalysis, // Passiamo anche l'oggetto originale completo
      domainAnalysis,
    };

  } catch (error) {
    console.error('[NMP] Errore analisi email:', error);
    throw error;
  }
}

// =====================================================================
// Notifiche Push
// =====================================================================

function sendPhishingNotification(subject, score) {
  const lang = chrome.i18n.getUILanguage().startsWith('it') ? 'it' : 'en';
  const title = lang === 'it' ? '⚠️ Email Sospetta Rilevata' : '⚠️ Suspicious Email Detected';
  const message = lang === 'it'
    ? `Punteggio: ${score}/5 - "${subject || 'Senza oggetto'}"`
    : `Score: ${score}/5 - "${subject || 'No subject'}"`;

  chrome.notifications.create({
    type: 'basic',
    iconUrl: chrome.runtime.getURL('icons/icon128.png'),
    title,
    message,
    priority: 2,
  });
}

// =====================================================================
// Installazione e Aggiornamento
// =====================================================================

chrome.runtime.onInstalled.addListener(({ reason }) => {
  if (reason === 'install') {
    chrome.storage.local.set({
      settings: {
        notificationsEnabled: true,
        autoAnalyze: true,
        proxyUrl: CONFIG.PROXY_BASE_URL,
      }
    });
  }
});
