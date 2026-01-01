Comportati come un senior software developer C# specializzato in autenticazione jwt in C#.

---
🧠 PROMPT DEFINITIVO – ASP.NET Core 8 Secure Auth (Gold Standard++)
Crea un progetto ASP.NET Core 8 – Minimal API in C# con autenticazione enterprise-grade, cookie-based, security-first.
Il risultato deve essere copiabile, compilabile e testabile.

---
🎯 Obiettivo Architetturale
JWT minimale (reference token)
Sessione server-side su DB
Revoca immediata
CSRF hardened (DB ↔ Header)
---

🔐 JWT (OBBLIGATORIO)
Algoritmo: HMAC-SHA256
Payload SOLO:
sub (sessionId)
jti
iat
exp
iss, aud

❌ Vietato inserire dati utente
Chiave
Minimo 32 caratteri
Da appsettings.json → Jwt:SecretKey
Lancia eccezione se mancante

---

🍪 Cookie
Nome: access_token
Flag obbligatori:
HttpOnly = true
Secure = true (configurabile dev)
SameSite = Strict
Path = /
MaxAge = exp JWT

---

🗄️ Sessione Server-Side
Storage
SQLite
Dapper (❌ NO EF Core)

Schema

CREATE TABLE user_sessions (
  session_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  created_at_utc TEXT NOT NULL,
  expires_at_utc TEXT NOT NULL,
  revoked_at_utc TEXT NULL,
  user_data_json TEXT NOT NULL,
  csrf_token TEXT NOT NULL
);

Timestamp
ISO 8601 obbligatorio
Salvare: DateTime.UtcNow.ToString("O")
Leggere: DateTime.Parse(x).ToUniversalTime()
---

🛡️ CSRF (OBBLIGATORIO – HARDENED)
Synchronized Token Pattern
Token CSRF:
generato dal server
salvato solo nel DB
Client → header X-CSRF-Token

Middleware:
legge sessione da HttpContext.Items["session"]
confronta header ↔ DB
Cookie csrf_token opzionale (DX)
❌ Vietato cookie↔header only.

---

🧱 Middleware
Ordine OBBLIGATORIO
1. UseCookieJwtAuth() → carica sessione
2. UseCsrfProtection() → usa sessione
3. Map endpoints

⚠️ Ordine errato = CSRF rotto.
JWT Middleware
Valida firma / exp / iss / aud
Errori JWT → ignora token, non eccezioni
401 solo negli endpoint protetti

---

🌐 API

POST /login
Fake auth demo/demo
Crea sessione DB
Genera JWT
Set cookie
Return:
   { "ok": true, "csrfToken": "..." }
// TODO PROD: BCrypt.Verify
// TODO PROD: rate limiting
// TODO PROD: logging tentativi falliti
GET /me (protetto)
POST /logout (protetto)
Revoca sessione

Cancella cookie

GET /health

---

📦 Pacchetti NuGet (VERSIONI FISSE)
Dapper 2.1.35
Microsoft.Data.Sqlite 8.0.0
System.IdentityModel.Tokens.Jwt 7.2.0

---

📁 File richiesti
Program.cs
appsettings.json
Models/UserSession.cs
Services/JwtTokenService.cs
Data/SessionRepository.cs
Data/DbInitializer.cs
Middleware/CookieJwtAuthMiddleware.cs
Middleware/CsrfMiddleware.cs
.csproj

---

🧪 Testing OBBLIGATORIO

Fornire curl per:
1. Login (salva cookie)
2. GET /me
3. POST /logout con X-CSRF-Token



---

🚀 Hardening (commentato)

// TODO PROD: refresh token
// TODO PROD: cleanup background service
// TODO PROD: multi-device session mgmt
// TODO PROD: security logging

---

✅ Checklist finale
[ ] Compila senza warning
[ ] JWT contiene solo sub/jti/iat/exp/iss/aud
[ ] Cookie HttpOnly=true
[ ] CSRF = header ↔ DB
[ ] Middleware in ordine corretto
[ ] Tutti i file presenti
[ ] curl testabili

---

🎓 Output Atteso
Codice completo
Commenti security-oriented
Nessuna ambiguità architetturale
