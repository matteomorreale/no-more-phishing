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
  return new Promise((resolve, reject) => {
    chrome.identity.getAuthToken({ interactive }, (token) => {
      if (chrome.runtime.lastError) {
        if (!interactive) {
          resolve(null);
        } else {
          reject(new Error(chrome.runtime.lastError.message));
        }
        return;
      }
      authToken = token;
      resolve(token);
    });
  });
}

async function signOut() {
  return new Promise((resolve, reject) => {
    if (!authToken) {
      resolve();
      return;
    }
    chrome.identity.removeCachedAuthToken({ token: authToken }, () => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      authToken = null;
      resolve();
    });
  });
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
    const analyzer = new GmailAnalyzer(token, CONFIG.GMAIL_API_BASE);
    let emailData;

    if (threadId) {
      emailData = await analyzer.analyzeThread(threadId);
    } else {
      emailData = await analyzer.analyzeMessage(messageId);
    }

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
      urlAnalysis = await proxyClient.checkUrls(emailData.urls);
    }

    // 4. Analizza il dominio del mittente
    let domainAnalysis = { reputation: 'unknown', isBlacklisted: false };
    if (emailData.senderDomain) {
      domainAnalysis = await proxyClient.checkDomain(emailData.senderDomain);
    }

    // 5. Calcola lo score finale
    const calculator = new ScoreCalculator();
    const scoreResult = calculator.calculate({
      spf: emailData.spf,
      dkim: emailData.dkim,
      dmarc: emailData.dmarc,
      senderDomainMatch: emailData.senderDomainMatch,
      domainAnalysis,
      urlAnalysis,
      urgencyKeywords: emailData.urgencyKeywords,
      hasAttachments: emailData.hasAttachments,
      isReply: emailData.isReply,
    });

    // 6. Invia notifica se score basso
    if (scoreResult.score <= CONFIG.NOTIFICATION_THRESHOLD) {
      sendPhishingNotification(emailData.subject, scoreResult.score);
    }

    // 7. Restituisci il risultato completo
    return {
      score: scoreResult.score,
      details: scoreResult.details,
      emailData: {
        subject: emailData.subject,
        sender: emailData.sender,
        senderDomain: emailData.senderDomain,
        date: emailData.date,
        spf: emailData.spf,
        dkim: emailData.dkim,
        dmarc: emailData.dmarc,
        urls: emailData.urls,
        hasAttachments: emailData.hasAttachments,
        isThread: !!threadId,
        messageCount: emailData.messageCount || 1,
      },
      urlAnalysis,
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
