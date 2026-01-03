# Descrizione della solution SecureAuthMinimalApi

Panoramica rapida della solution .NET 8 con Minimal API protetta da JWT in cookie HttpOnly, sessioni server-side su SQLite e client WinForms di esempio.

## Progetti e cartelle
- `SecureAuthMinimalApi.sln`: solution che include API, test e client.
- `src/SecureAuthMinimalApi`: API minimale con Program.cs, middleware, servizi, repository Dapper e configurazione (`appsettings.json`, `appsettings.Development.json`, `appsettings.guida.md`).
- `tests/SecureAuthMinimalApi.Tests`: test di integrazione xUnit.
- `clients/WinFormsClient`: client WinForms di esempio che esercita i flussi API con cookie + header CSRF.
- `postman`: collezioni per chiamate manuali.

## Flussi ed endpoint principali (API)
- Salute: `/health` liveness, `/live` quick check, `/ready` readiness con verifica DB e config JWT.
- Registrazione: `/register` crea utente con hash bcrypt e token di conferma email (24h).
- Login: `/login` verifica credenziali, applica throttle persistente, richiede email confermata, crea sessione DB, emette cookie `access_token` HttpOnly SameSite=Strict + CSRF token in risposta.
- MFA: se l'utente ha TOTP registrato il login risponde `mfa_required` con `challengeId`; `/login/confirm-mfa` valida il TOTP e completa la sessione.
- Sessione: `/me` restituisce dati sessione attiva; idle timeout opzionale via `Session:IdleMinutes` aggiornato dal middleware.
- Logout: `/logout` revoca sessione e refresh associato; `/logout-all` revoca tutte le refresh dell'utente, opzionalmente cancella cookie device.
- Refresh/remember-me: `/refresh` ruota refresh token legato a cookie `device_id` (binding UA+device+scadenza) ed emette nuovo access+refresh+CSRF.
- Id token: `/login` e `/login/confirm-mfa` restituiscono anche `idToken` (JWT identita') nel body, con claim minimi (sub, iat, auth_time, amr; nonce opzionale). Firmato con chiave dedicata `IdToken` (RSA se configurata, altrimenti HMAC dev). Validare firma/issuer/audience/scadenza lato client.
- MFA management: `/mfa/setup` genera segreto e otpauth URI, `/mfa/disable` azzera il segreto.
- Email: `/confirm-email` conferma usando il token registrazione.
- Introspezione: `/introspect` legge JWT (header Bearer o cookie) e restituisce stato sessione (attiva, revocata, scaduta, non trovata).

## Sicurezza e middleware
- Ordine middleware obbligato: `UseCookieJwtAuth` (estrae JWT da cookie, valida iss/aud/firma/scadenza e carica sessione da DB con controllo revoca/idle) -> `UseCsrfProtection` (Synchronized Token Pattern con token solo server-side) -> endpoint.
- Cookie `access_token`: HttpOnly, SameSite=Strict, Path=/, Secure forzato fuori da Development, durata allineata a JWT.
- Header hardening non in Development: HSTS, HTTPS redirect, X-Frame-Options=DENY, X-Content-Type-Options=nosniff, Referrer-Policy=no-referrer, X-XSS-Protection=0, CSP `default-src 'none'`.
- Throttle login persistente in `login_throttle` (lock dopo soglia fallimenti), audit login in `login_audit`.
- Refresh token con rotation obbligatoria e binding UA + cookie `device_id`; opzione `Device:ClearOnLogoutAll` per revocare device.
- MFA TOTP con segreto cifrato tramite Data Protection; challenge con vincoli tempo, tentativi, UA/IP configurabili.
- Cleanup periodico: `ExpiredCleanupService` elimina a intervalli i record scaduti o revocati (sessioni, refresh token, challenge MFA) secondo config `Cleanup:*`.
- Validazioni config: secret JWT minimo 32 char, AccessTokenMinutes > 0, warning se Cookie:RequireSecure disabilitato fuori Dev.

## Schema dati (SQLite, vedi `Data/*.cs` e `DbInitializer`)
- `users`: credenziali bcrypt, email e token conferma, segreto TOTP protetto.
- `user_sessions`: sessioni server-side con JSON user_data, CSRF token, last_seen per idle timeout.
- `login_throttle`: conteggio fallimenti e lock fino a timestamp.
- `login_audit`: audit login con outcome, IP, UA, dettaglio.
- `refresh_tokens`: refresh persistenti con binding dispositivo, rotazione e motivo revoca.
- `mfa_challenges`: challenge TOTP con scadenza, UA/IP e conteggio tentativi.
- Indici di supporto su hash refresh e su campi di scadenza/revoca per cleanup batch.
- Seed demo: utente `demo/demo` creato se assente.

## Configurazione
- File di riferimento: `src/SecureAuthMinimalApi/appsettings.guida.md` (descrive tutte le chiavi Jwt, Cookie, LoginThrottle, PasswordPolicy, RememberMe, Device, Session, Mfa, Cleanup, Serilog, Logging, Tests).
- Connessione DB in `ConnectionStrings:Sqlite` (default SQLite su file); `Tests:SkipDbInit` permette di saltare init in scenari di test.
- Password policy e normalizzazione username/email configurabili via appsettings.
- Cleanup: `Cleanup:Enabled`, `Cleanup:IntervalSeconds`, `Cleanup:BatchSize`, `Cleanup:MaxIterationsPerRun` regolano il job di rimozione record scaduti.

## Logging e osservabilita
- Serilog configurato da appsettings (sink file e console); log di request/response in Program.cs con esito e path; header `X-Session-Expires-At` e `X-Session-Idle-Remaining` esposti dal middleware.
- Log iniziale a startup con riepilogo configurazione attiva (ambiente, URL, DB, JWT, policy password/username/MFA, sessione, cleanup, throttle, remember/device) stampato in console.
- Controlli console: `P` mette in pausa rispondendo 503, `P` di nuovo riprende; `S` esegue arresto sicuro; warning se input console non disponibile.

## Testing
- Progetto `tests/SecureAuthMinimalApi.Tests`: test di integrazione (xUnit) che coprono login/me/logout, cookie flags, CSRF, registrazione, throttle lockout, audit, idle timeout, refresh rotation, MFA TOTP, Serilog smoke, id_token e cleanup scadenze.
- Esecuzione: `dotnet test` dalla root oppure `dotnet test tests/SecureAuthMinimalApi.Tests/SecureAuthMinimalApi.Tests.csproj`.
- Id token: firma valida con chiave `IdToken` (RSA se presente, HMAC in dev), claim minimi (sub, iat/auth_time, amr pwd/mfa, nonce opzionale, username; email se `IdToken:IncludeEmail=true`); validare issuer/audience/scadenza lato client.
- Cleanup: `CleanupServiceTests` verificano rimozione record scaduti, batch/disable e non cancellano record validi.

## Client WinForms
- `clients/WinFormsClient` (.NET 8): UI che esegue registrazione, conferma email, login con remember-me, gestione MFA (setup/confirm/disable), refresh, me, logout usando cookie HttpOnly e header `X-CSRF-Token`. Gestisce visualizzazione token, device-id, countdown sessione e log eventi (id_token solo log in dev, non persistito).
- Avvio: `dotnet run --project clients/WinFormsClient/WinFormsClient.csproj` (richiede API in esecuzione e URL configurato nella UI).

## Build ed esecuzione API
- Build API: `dotnet build src/SecureAuthMinimalApi/SecureAuthMinimalApi.csproj`
- Build solution completa: `dotnet build SecureAuthMinimalApi.sln`
- Run API locale: `dotnet run --project src/SecureAuthMinimalApi/SecureAuthMinimalApi.csproj` (in Dev puoi impostare `Cookie:RequireSecure=false`).
