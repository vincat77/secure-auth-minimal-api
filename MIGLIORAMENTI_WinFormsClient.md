# WinFormsClient - Miglioramenti proposti

Obiettivo: rendere il client WinForms più robusto, sicuro e usabile con l'API SecureAuthMinimalApi.

## UX e flusso
- Aggiungere stati chiari: “Non autenticato”, “Autenticato”, “Sessione scaduta/revocata”.
- Mostrare/aggiornare la sessione corrente (sessionId, exp) e l’utente loggato.
- Pannello log eventi (timestamp + azione + esito) con livelli Info/Errore.
- Spinner/disable sui pulsanti durante le chiamate HTTP; messaggi di errore localizzati.

## Sicurezza
- Gestione cookie: usare `HttpClientHandler` dedicato con `CookieContainer` isolato; pulire cookie su logout.
- Validare il server certificate solo in ambienti consentiti (niente bypass permanente di SSL).
- Gestire CSRF token: conservarlo in memoria sicura e inviarlo su logout/azioni protette.
- Non loggare mai password o token; mascherare eventuali dati sensibili nei log UI.

## Configurazione
- Rendere configurabili endpoint base URL, timeout, e flag `RequireSecure`/HTTP per dev.
- Gestire profili (sviluppo/test/prod) con salvataggio su file di impostazioni utente.
- Permettere l’inserimento del TOTP per login MFA e setup MFA (visualizzare otpauth/QR se necessario).

## Resilienza
- Timeout e retry con backoff per le chiamate HTTP; cancellazione con `CancellationToken`.
- Gestire errori strutturati dell’API (es. `unauthorized`, `csrf_invalid`, `mfa_required`) e mostrarli all’utente.
- Rilevare sessione scaduta/revocata (es. /me 401) e forzare re-login con un messaggio chiaro.

## Testabilità e manutenzione
- Separare UI da logica: introdurre un client service (es. `AuthApiClient`) con metodi `LoginAsync`, `MeAsync`, `LogoutAsync`, `SetupMfaAsync`.
- Aggiungere logica di serializzazione/deserializzazione centralizzata (System.Text.Json con naming policy).
- Prevedere interfacce per mockare l’API e scrivere test di integrazione del client (anche con `HttpMessageHandler` finto).

## Funzionalità aggiuntive
- Supporto MFA: campo TOTP in login; pulsante “Setup MFA” che chiama `/mfa/setup` e mostra secret/URI.
- Introspezione: pulsante per chiamare `/introspect` e visualizzare stato sessione.
- Opzione “remember me” (se introdotta lato API) gestendo il cookie con una durata maggiore.

## Piano minimo (step rapidi)
1) Log eventi UI: aggiungere un pannello log separato dall’output grezzo, con livello Info/Errore e timestamp.
2) Spinner/disable: disabilitare pulsanti durante le chiamate HTTP e mostrare un testo “In corso...” vicino ai pulsanti.
3) Messaggi localizzati: uniformare i messaggi di errore/successo in italiano, senza dati sensibili.
4) TOTP in login: aggiungere textbox facoltativa per `totpCode` e usarla nel payload di login; opzionale bottone “Setup MFA” che chiama `/mfa/setup` e mostra il secret.
