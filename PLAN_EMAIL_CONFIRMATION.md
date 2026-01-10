# Piano: requisito conferma email parametrico

## Obiettivo
Permettere di rendere opzionale la verifica email durante la registrazione/login tramite configurazione, mantenendo il comportamento attuale come default.

## Passi
1) Test (prima): estendere `tests/SecureAuthMinimalApi.Tests/ApiTests.cs` con nuovi casi nominati chiaramente.
   - Default (flag mancante/true): POST /login dopo /register senza conferma deve restare 403 email_not_confirmed (verifica payload e che EmailConfirmed resti 0 in DB). Questo test già esiste: mantenerlo come baseline.
   - Flag disabilitato `EmailConfirmation:Required=false` via `CreateFactory` override: POST /login dopo /register senza conferma deve passare (200) e restituire cookie/csrf; in DB EmailConfirmed deve essere 0 e token+exp devono restare valorizzati per uso successivo. Aggiungere poi conferma e verificare che passi a 1 e token/exp vengano nullati.
   - Eventuale test di regressione: conferma email con token valido deve continuare a funzionare anche quando Required=false.
   - Assicurarsi di non rompere test esistenti su login bloccato: usare naming dedicato (es. `Login_allows_when_email_confirmation_not_required`).

2) Config: introdurre `EmailConfirmation:Required` in `Program.cs` (default true) e passarlo agli endpoint.
   - Calcolare bool required = config.GetValue<bool?>("EmailConfirmation:Required") ?? true.
   - Passare a `MapLogin` un parametro aggiuntivo per decidere se bloccare login quando EmailConfirmed=false.
   - `MapRegister`: generazione token invariata; output continua a includere token/exp.
   - Se necessario, estendere `EndpointUtilities.Normalize...` non richiesto; nessun input nuovo.

3) Logica applicativa: applicare il flag nel flusso login.
   - In `LoginEndpoints`, sostituire il check “if (!user.EmailConfirmed && !demo)” con un controllo condizionale sul flag; mantenere audit “email_not_confirmed” solo quando required è true.
   - Nessun cambio su conferma: /confirm-email rimane identico per marcare confermato e ripulire token.
   - Documentare il nuovo parametro in `appsettings*.json` e, se serve, nota nel README/appsettings.guida.

4) Verifica finale: eseguire i test interessati (ApiTests, almeno i nuovi + quelli esistenti che toccano login/confirm) e rigenerare tag con `tools\\update-tags.ps1`. Includere eventuale comando `dotnet test` se tempo.

## Estensioni test aggiuntivi (combos)
- Email non richiesta + MFA attiva: con `EmailConfirmation:Required=false` e utente con TOTP configurato, login deve restituire `mfa_required` (non 403) e creare challenge.
- Email non richiesta + RememberMe: login con `RememberMe=true` e flag email disabilitato deve restituire `rememberIssued=true` e persistere il refresh token.
- Registrazione fallita (email invalida): `/register` con email senza `@` deve restituire 400 `invalid_input` con `email_invalid`.
- Registrazione fallita (password policy): con policy severa e password debole, `/register` deve restituire 400 `password_policy_failed` con lista errori.
- TOTP flow: setup/confirm MFA e poi login deve richiedere MFA e accettare il codice corretto; verificare id_token/sessione coerenti (se già previsto).
- RememberMe disabilitato: con `RememberMe:Days=0` (o simile), login con `RememberMe=true` non deve emettere refresh/device (`rememberIssued=false`).
