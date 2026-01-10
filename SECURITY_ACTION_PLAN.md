# Piano d'azione sicurezza/qualità – SecureAuthMinimalApi

## Obiettivi
Correggere criticità (DoS/log leak/seed demo) e rendere più affidabili configurazione e schema.

## Priorità Alta (da eseguire subito)
1) MFA log sanitization  
   - File: `Endpoints/ConfirmMfaEndpoints.cs`.  
   - Azione: rimuovere `TotpCode` dai log (nessun valore del codice). Loggare solo outcome (`invalid_totp`), challengeId, userId, IP/UA opzionali. Punto da toccare: log warning su TOTP errato in `ConfirmMfaEndpoints.cs:80+` (contains `code={Code}`).  
   - Verifica: grep `code=` non deve restituire log; test MFA invariati.

2) CSRF FixedTimeEquals safe  
   - File: `Middleware/CsrfMiddleware.cs` (FixedTimeEquals a riga ~68).  
   - Azione: se lunghezze diverse, ritorna `false` prima di `CryptographicOperations.FixedTimeEquals` per evitare `ArgumentException` su input malformati.  
   - Verifica: test CSRF esistenti; simulare header corto non genera 500.

3) Seed utente demo sicuro  
   - File: `Data/DbInitializer.cs`.  
   - Azione: creare utente demo solo se `IHostEnvironment.IsDevelopment()` oppure `Seed:Enabled=true` (default false). Password demo solo in dev/doc. Punto da toccare: blocco seed in fondo a `DbInitializer` (seedCheck/seedInsert per username 'demo').  
   - Verifica: avvio in prod non crea demo; in dev con flag on sì.

## Priorità Media
4) Refresh UA binding configurabile  
   - File: endpoint refresh (`Endpoints/RefreshEndpoints.cs`, controllo UA vs stored.UserAgent).  
   - Azione: introdurre `Refresh:RequireUserAgentMatch` (default false). Se false, non bloccare per UA mismatch; device cookie resta binding primario.  
   - Verifica: test refresh con UA diverso passano quando flag=false.

5) Cookie SameSite/RequireSecure hardening  
   - File: `Endpoints/LoginEndpoints.cs` (emissione refresh/device) – vedi blocco config `RememberMe:SameSite` e `Device:SameSite`.  
   - Azione: in prod forza sempre `Secure=true`; vieta `SameSite=None` per refresh/device salvo flag `AllowSameSiteNone` (default false). Log warning se disattivato.  
   - Verifica: test login/refresh/device in ambiente “Production” rispettano i flag.

6) EnsureColumn robusto  
   - File: `Data/DbInitializer.cs`.  
   - Azione: leggere `PRAGMA table_info` come record/anonimo e controllare il campo `name` invece di `Query<string>/Contains` per evitare alter non affidabili.  
   - Verifica: init su DB esistente non ripete alter, nessun falso positivo/negativo.

## Priorità Bassa / Miglioramenti
7) Centralizzare config in Options  
   - Azione: spostare policy (password, remember/device/cookie, refresh UA) da IConfiguration a IOptions<T> con validazione all’avvio, riducendo divergenze tra endpoint/test.  
   - Verifica: meno duplicazioni, default documentati.

8) Date storage  
   - Azione: valutare DateTimeOffset o epoch (long) per scadenze/revoke/last_seen; oggi TEXT “O”.  
   - Verifica: migrazione schema + adeguamento repository/mapper.

9) Migrazioni schema (medium-long term)  
   - Azione: introdurre migrazioni (EF Core o tool SQL) per upgrade ripetibili, eliminando EnsureColumn manuale.  
   - Verifica: comando migration/apply funzionante in CI.

## Test/Verifica
- `dotnet test tests/SecureAuthMinimalApi.Tests/SecureAuthMinimalApi.Tests.csproj`
- Smoke manuale in dev: login/mfa/refresh/reset dopo fix (assenza TotpCode nei log, CSRF robusto, demo non creato fuori dev).


