# SecureAuthMinimalApi

API minimale .NET 8 con autenticazione JWT via cookie (reference token) e sessioni server-side su SQLite (Dapper), hardening CSRF e revoca immediata.

## Struttura
- `src/SecureAuthMinimalApi`: progetto API principale (Program, Middleware, Services, Data, Models, appsettings).
- `tests/SecureAuthMinimalApi.Tests`: progetto xUnit di integrazione.
- `SecureAuthMinimalApi.sln`: solution che include entrambi.

## Funzionalità implementate
- JWT HMAC-SHA256 con payload minimale (sub/jti/iat/exp/iss/aud), validazione issuer/audience/firma.
- Cookie `access_token` HttpOnly, SameSite=Strict, Path=/, Secure configurabile (RequireSecure).
- Sessioni server-side in SQLite con Dapper; revoca e scadenza lato DB.
- CSRF “synchronized token”: token solo DB, richiesto in header `X-CSRF-Token` per metodi unsafe.
- Middleware in ordine obbligato: cookie JWT → CSRF → endpoint.
- Endpoint: `/register` (credenziali da DB), `/login`, `/me` protetto, `/logout` con revoca, `/health`, `/introspect`, `/mfa/setup`.
- Registrazione utenti con password hash bcrypt; policy password configurabile (`PasswordPolicy`: minLength, requireUpper/Lower/Digit/Symbol).
- Login con throttle persistente su DB (lockout 5 fallimenti/5 min), audit login persistente su DB (success/fail/lockout con IP/UA/outcome).
- MFA TOTP opzionale: `/mfa/setup` genera segreto/otpauth; login richiede `totpCode` se attivo.

## Test (xUnit)
Coprono flow e hardening:
- Happy path login/me/logout, health.
- Claim JWT minimali e validabili.
- Cookie flags (Secure on/off), max-age.
- Credenziali errate, token manomesso, issuer/audience errati, sessione revocata o scaduta.
- CSRF assente/errato su logout, assenza cookie su /me.
- Registrazione/login dinamici, duplicati, password troppo corta, trim username, lockout/lockout persistente dopo tentativi falliti, audit login success/fail.
- MFA TOTP: setup, login senza/errato `totpCode` → 401, login con codice valido → OK.

Esegui:
- Tutti i test: `dotnet test`
- Solo test project: `dotnet test tests/SecureAuthMinimalApi.Tests/SecureAuthMinimalApi.Tests.csproj`

## Build
Da root repo:
- API: `dotnet build src/SecureAuthMinimalApi/SecureAuthMinimalApi.csproj`
- Tutto (solution): `dotnet build SecureAuthMinimalApi.sln`

## Run locale
- Avvia API: `dotnet run --project src/SecureAuthMinimalApi/SecureAuthMinimalApi.csproj`
- Config: `appsettings.json` in `src/SecureAuthMinimalApi`; per sviluppo imposta `Cookie:RequireSecure=false`.

Nota test: il progetto di test usa DB SQLite temporaneo e setta `Cookie:RequireSecure=false` per simulare ambiente HTTP locale.
