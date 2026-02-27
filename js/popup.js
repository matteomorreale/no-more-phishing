/**
 * No More Phishing - Popup Script
 * @author Matteo Morreale
 * @version 1.0.0
 *
 * Gestisce l'interfaccia del popup: autenticazione, impostazioni,
 * legenda score e internazionalizzazione.
 */

(function () {
  'use strict';

  // ===================================================================
  // Internazionalizzazione
  // ===================================================================

  const STRINGS = {
    it: {
      statusActive: 'Attivo — analisi email in corso',
      statusInactive: 'Inattivo',
      connectedAccount: 'Account connesso',
      authDesc: 'Accedi con il tuo account Google per iniziare ad analizzare le email.',
      signIn: 'Accedi con Google',
      legendTitle: 'Legenda Punteggi',
      legend5: 'Molto Affidabile',
      legend4: 'Affidabile',
      legend3: 'Incerto',
      legend2: 'Sospetto',
      legend1: 'Pericoloso',
      settingsTitle: 'Impostazioni',
      notificationsLabel: 'Notifiche Push',
      notificationsDesc: 'Avvisa quando viene rilevata un\'email sospetta',
      autoLabel: 'Analisi Automatica',
      autoDesc: 'Analizza le email automaticamente all\'apertura',
      proxyLabel: 'URL Server Proxy',
      saveText: 'Salva',
      signoutText: 'Disconnetti',
      saved: 'Salvato!',
      footerLink: 'GitHub',
    },
    en: {
      statusActive: 'Active — analyzing emails',
      statusInactive: 'Inactive',
      connectedAccount: 'Connected account',
      authDesc: 'Sign in with your Google account to start analyzing emails.',
      signIn: 'Sign in with Google',
      legendTitle: 'Score Legend',
      legend5: 'Very Trustworthy',
      legend4: 'Trustworthy',
      legend3: 'Uncertain',
      legend2: 'Suspicious',
      legend1: 'Dangerous',
      settingsTitle: 'Settings',
      notificationsLabel: 'Push Notifications',
      notificationsDesc: 'Alert when suspicious email detected',
      autoLabel: 'Auto Analyze',
      autoDesc: 'Analyze emails automatically on open',
      proxyLabel: 'Proxy Server URL',
      saveText: 'Save Settings',
      signoutText: 'Sign Out',
      saved: 'Saved!',
      footerLink: 'GitHub',
    },
  };

  function getLang() {
    const uiLang = chrome.i18n.getUILanguage();
    return uiLang.startsWith('it') ? 'it' : 'en';
  }

  function t(key) {
    const lang = getLang();
    return STRINGS[lang][key] || STRINGS.en[key] || key;
  }

  function applyI18n() {
    document.getElementById('nmp-auth-desc').textContent = t('authDesc');
    document.getElementById('nmp-signin-text').textContent = t('signIn');
    document.getElementById('nmp-status-text').textContent = t('statusActive');
    document.getElementById('nmp-user-label').textContent = t('connectedAccount');
    document.getElementById('nmp-legend-title').textContent = t('legendTitle');
    document.getElementById('nmp-legend-5').textContent = t('legend5');
    document.getElementById('nmp-legend-4').textContent = t('legend4');
    document.getElementById('nmp-legend-3').textContent = t('legend3');
    document.getElementById('nmp-legend-2').textContent = t('legend2');
    document.getElementById('nmp-legend-1').textContent = t('legend1');
    document.getElementById('nmp-settings-title').textContent = t('settingsTitle');
    document.getElementById('nmp-setting-notifications-label').textContent = t('notificationsLabel');
    document.getElementById('nmp-setting-notifications-desc').textContent = t('notificationsDesc');
    document.getElementById('nmp-setting-auto-label').textContent = t('autoLabel');
    document.getElementById('nmp-setting-auto-desc').textContent = t('autoDesc');
    document.getElementById('nmp-setting-proxy-label').textContent = t('proxyLabel');
    document.getElementById('nmp-save-text').textContent = t('saveText');
    document.getElementById('nmp-signout-text').textContent = t('signoutText');
    document.getElementById('nmp-footer-link').textContent = t('footerLink');
  }

  // ===================================================================
  // Inizializzazione
  // ===================================================================

  async function init() {
    applyI18n();
    await checkAuthStatus();
    setupEventListeners();
    loadSettings();
  }

  // ===================================================================
  // Verifica stato autenticazione
  // ===================================================================

  async function checkAuthStatus() {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage({ type: 'GET_AUTH_STATUS' }, (response) => {
        if (response?.authenticated) {
          showAuthenticatedUI();
        } else {
          showUnauthenticatedUI();
        }
        resolve();
      });
    });
  }

  function showAuthenticatedUI() {
    document.getElementById('nmp-auth-section').style.display = 'none';
    document.getElementById('nmp-status-section').style.display = 'block';
    document.getElementById('nmp-legend-section').style.display = 'block';
  }

  function showUnauthenticatedUI() {
    document.getElementById('nmp-auth-section').style.display = 'block';
    document.getElementById('nmp-status-section').style.display = 'none';
    document.getElementById('nmp-legend-section').style.display = 'none';
  }

  // ===================================================================
  // Event Listeners
  // ===================================================================

  function setupEventListeners() {
    // Sign In
    document.getElementById('nmp-popup-signin')?.addEventListener('click', async () => {
      const btn = document.getElementById('nmp-popup-signin');
      btn.disabled = true;
      btn.style.opacity = '0.7';

      chrome.runtime.sendMessage({ type: 'SIGN_IN' }, (response) => {
        btn.disabled = false;
        btn.style.opacity = '1';
        if (response?.success) {
          showAuthenticatedUI();
        }
      });
    });

    // Settings toggle
    document.getElementById('nmp-settings-btn')?.addEventListener('click', () => {
      document.getElementById('nmp-settings-panel').style.display = 'flex';
    });

    document.getElementById('nmp-back-btn')?.addEventListener('click', () => {
      document.getElementById('nmp-settings-panel').style.display = 'none';
    });

    // Save Settings
    document.getElementById('nmp-save-settings')?.addEventListener('click', () => {
      saveSettings();
    });

    // Sign Out
    document.getElementById('nmp-signout-btn')?.addEventListener('click', () => {
      chrome.runtime.sendMessage({ type: 'SIGN_OUT' }, () => {
        showUnauthenticatedUI();
        document.getElementById('nmp-settings-panel').style.display = 'none';
      });
    });
  }

  // ===================================================================
  // Gestione Impostazioni
  // ===================================================================

  function loadSettings() {
    chrome.storage.local.get('settings', (data) => {
      const settings = data.settings || {};
      const notifEl = document.getElementById('nmp-setting-notifications');
      const autoEl = document.getElementById('nmp-setting-auto');
      const proxyEl = document.getElementById('nmp-setting-proxy');

      if (notifEl) notifEl.checked = settings.notificationsEnabled !== false;
      if (autoEl) autoEl.checked = settings.autoAnalyze !== false;
      if (proxyEl) proxyEl.value = settings.proxyUrl || '';
    });
  }

  function saveSettings() {
    const settings = {
      notificationsEnabled: document.getElementById('nmp-setting-notifications')?.checked ?? true,
      autoAnalyze: document.getElementById('nmp-setting-auto')?.checked ?? true,
      proxyUrl: document.getElementById('nmp-setting-proxy')?.value || '',
    };

    chrome.storage.local.set({ settings }, () => {
      const btn = document.getElementById('nmp-save-settings');
      const originalText = btn.querySelector('#nmp-save-text').textContent;
      btn.querySelector('#nmp-save-text').textContent = t('saved');
      btn.style.background = '#16a34a';
      setTimeout(() => {
        btn.querySelector('#nmp-save-text').textContent = originalText;
        btn.style.background = '';
      }, 1500);
    });
  }

  // ===================================================================
  // Avvio
  // ===================================================================

  document.addEventListener('DOMContentLoaded', init);

})();
