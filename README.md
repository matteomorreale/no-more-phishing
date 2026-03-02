# No More Phishing — Proteggi le tue email dal phishing

**No More Phishing** è un'estensione per browser Chrome e Chromium che analizza automaticamente ogni email che apri su Gmail, assegnando un punteggio di affidabilità da 1 a 5 per aiutarti a identificare tentativi di phishing e truffe online.

🌐 **Sito Ufficiale:** [nomorephishing.matteomorreale.it](https://nomorephishing.matteomorreale.it/)

## 🚀 Funzionalità Principali

L'estensione lavora in tempo reale per garantirti la massima sicurezza:

*   **Punteggio di Affidabilità (1-5)**: Un indicatore immediato per sapere se fidarti dell'email.
*   **Verifica Protocolli di Sicurezza**: Controlla SPF, DKIM e DMARC per assicurarsi che il mittente sia autenticato.
*   **Reputazione del Dominio**: Verifica il dominio del mittente su database globali come Google Safe Browsing e VirusTotal.
*   **Analisi Link Interni**: Scansiona tutti i link presenti nel corpo dell'email per rilevare URL malevoli o di phishing.
*   **Rilevamento Parole Chiave**: Identifica frasi sospette tipiche del phishing (es. "verifica il tuo account", "azione urgente").
*   **Supporto Thread Gmail**: Analizza correttamente ogni singolo messaggio all'interno delle conversazioni.
*   **Notifiche Push**: Ti avvisa immediatamente se viene rilevata un'email pericolosa.

## 📊 Come Funziona il Punteggio

Il punteggio viene calcolato combinando oltre 8 parametri di sicurezza:

*   **5 - Molto Affidabile**: Tutti i controlli superati (SPF/DKIM/DMARC validi, dominio sicuro).
*   **4 - Affidabile**: Qualche avviso minore, ma generalmente sicuro.
*   **3 - Incerto**: Procedere con cautela, alcuni parametri non sono verificabili.
*   **2 - Sospetto**: Diversi segnali di allarme rilevati.
*   **1 - Pericoloso**: Quasi certamente un tentativo di phishing.

## 🛠️ Installazione

### 1. Scarica l'estensione
Clona questo repository o scarica il codice sorgente sul tuo computer.

### 2. Carica in Chrome/Chromium
1.  Apri il browser (Chrome, Brave, Edge, ecc.).
2.  Vai su `chrome://extensions`.
3.  Attiva la **Modalità sviluppatore** (in alto a destra).
4.  Clicca su **Carica estensione non pacchettizzata**.
5.  Seleziona la cartella del progetto scaricato.

### 3. Configurazione Backend (Proxy)
L'estensione richiede un backend PHP per comunicare con le API di sicurezza (Google Safe Browsing, VirusTotal).
1.  Carica i file del backend PHP sul tuo server VPS o hosting.
2.  Inserisci le tue chiavi API nel file di configurazione del backend.
3.  Assicurati che l'estensione punti all'URL corretto del tuo server proxy.

### 4. Accedi con Google
1.  Apri Gmail.
2.  L'estensione ti chiederà di autorizzare l'accesso tramite OAuth 2.0 per leggere le intestazioni delle email (necessario per SPF/DKIM).
3.  Una volta autorizzato, sei protetto!

## 🔒 Privacy e Sicurezza

*   **Open Source**: Il codice è trasparente e verificabile da chiunque.
*   **Dati Locali**: L'analisi avviene principalmente nel browser e tramite il tuo server proxy privato.
*   **Credenziali**: L'autenticazione avviene tramite OAuth 2.0 ufficiale di Google; le tue password non vengono mai condivise con l'estensione.

## 👨‍💻 Autore

Sviluppato da **Matteo Morreale**.

---
*Progetto Open Source per la sicurezza informatica.*
