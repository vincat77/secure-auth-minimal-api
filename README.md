# SecureAuthMinimalApi

Progetto di riferimento per autenticazione web sicura in .NET 8: Minimal API con JWT via cookie HttpOnly, sessioni server-side su SQLite e CSRF hardening, pensata per mostrare pattern pratici (login, refresh, MFA) riutilizzabili in app reali.

## Installazione
`dotnet restore`

## Utilizzo
```bash
dotnet run --project src/SecureAuthMinimalApi/SecureAuthMinimalApi.csproj
```

Esempio minimo (login e lettura profilo):
```bash
curl -i -X POST http://localhost:5000/login ^
  -H "Content-Type: application/json" ^
  -d "{\"username\":\"demo\",\"password\":\"demo\"}" ^
  -c cookies.txt

curl -i http://localhost:5000/me -b cookies.txt
```

## Esempi di utilizzo
Logout con CSRF (sostituisci `<csrfToken>` con quello ricevuto da `/login`):
```bash
curl -i -X POST http://localhost:5000/logout ^
  -H "X-CSRF-Token: <csrfToken>" ^
  -b cookies.txt
```

Refresh sessione (ruota refresh token e rinnova access/CSRF):
```bash
curl -i -X POST http://localhost:5000/refresh ^
  -H "X-CSRF-Token: <csrfToken>" ^
  -b cookies.txt
```

Login con MFA (prima `POST /login`, poi `POST /login/confirm-mfa` con `challengeId` e `totpCode`):
```bash
curl -i -X POST http://localhost:5000/login/confirm-mfa ^
  -H "Content-Type: application/json" ^
  -d "{\"challengeId\":\"<id>\",\"totpCode\":\"123456\"}" ^
  -c cookies.txt
```

Registrazione utente:
```bash
curl -i -X POST http://localhost:5000/register ^
  -H "Content-Type: application/json" ^
  -d "{\"username\":\"mario\",\"password\":\"P@ssw0rd!\",\"email\":\"mario@example.com\"}"
```

Conferma email:
```bash
curl -i "http://localhost:5000/confirm-email?token=<token>"
```

Introspezione token (cookie o Bearer):
```bash
curl -i http://localhost:5000/introspect -b cookies.txt
```

## Stato
🚧 Progetto in fase iniziale. Feedback benvenuto.

## Funzionalita
- JWT HMAC-SHA256 minimale con claim essenziali.
- Cookie `access_token` HttpOnly, SameSite=Strict, Secure configurabile.
- Sessioni server-side su SQLite con revoca immediata.
- CSRF hardening con token solo server-side e header `X-CSRF-Token`.
- Login throttle persistente e audit login.
- Refresh token con rotation e binding dispositivo.
- MFA TOTP opzionale con challenge.
- Cleanup periodico record scaduti o revocati.

## Endpoint principali
- `POST /register`: crea utente con password hash.
- `POST /login`: login, set cookie, ritorna `csrfToken` e opzionale `idToken`.
- `POST /login/confirm-mfa`: completa login con TOTP.
- `GET /me`: profilo sessione attiva.
- `POST /logout` e `POST /logout-all`: revoca sessione/i.
- `POST /refresh`: ruota refresh token e rinnova access/CSRF.
- `GET /health` / `GET /live` / `GET /ready`: health checks.
- `GET /introspect`: stato sessione da token.
- `GET /confirm-email`: conferma email.

## Configurazione
File di riferimento: `src/SecureAuthMinimalApi/appsettings.guida.md`.
Impostazioni chiave:
- `Jwt:*` per issuer/audience/secret.
- `Cookie:RequireSecure` per sviluppo locale.
- `Session:*`, `LoginThrottle:*`, `PasswordPolicy:*`, `Mfa:*`, `Cleanup:*`.
- `ConnectionStrings:Sqlite` per il DB.

## Test
```bash
dotnet test
```

## Client di esempio
`clients/WinFormsClient` mostra i flussi completi con cookie HttpOnly e header CSRF.

## Contribuire
Issue e PR sono benvenute.

## Licenza
MIT. Vedi `LICENSE`.
