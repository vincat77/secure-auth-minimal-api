## Piano operativo per produrre in sicurezza (SecureAuthMinimalApi)

### Obiettivo
Portare il servizio in produzione coprendo i minimi operativi di sicurezza (rate limiting, gestione segreti, hardening TLS/cookie, logging pulito, errori coerenti, patching, config deploy).

### Azioni prioritarie (dettagliate)
- **Rate limiting & lockout**
  - Cosa fare: aggiungere rate limit globale/IP su `/login`, `/register`, `/refresh`, `/confirm-email`, oltre a quello già presente su `/password-reset/request`. Estendere lockout progressivo login con backoff.
  - Dove intervenire: nuovi middleware/servizi condivisi + uso in `LoginEndpoints.cs`, `RefreshEndpoints.cs`, `RegisterEndpoints.cs`, `ConfirmEmailEndpoints.cs` (oggi non presenti).
  - Perché: riduce credential stuffing e abusi massivi.

- **Gestione segreti**
  - Cosa fare: leggere `Jwt:SecretKey`, `TokenHashing:EmailConfirmPepper`, SMTP/DB da secret store (env var/KeyVault), documentare rotazione; rimuovere placeholder da `appsettings*.json`.
  - Dove intervenire: `Program.cs` binding options, pipeline di deploy, file di config.
  - Perché: evitare compromissioni da leak di config.

- **TLS e cookie hardening**
  - Cosa fare: imporre HTTPS/HSTS in prod; mantenere `Secure/HttpOnly/SameSite` forzati; bloccare `AllowSameSiteNone` salvo flag esplicito e warning; verificare header di sicurezza.
  - Dove intervenire: configurazione host/proxy + check in `UseSecurityHeaders` e cookie options (Login/Refresh/Logout/MFA).
  - Perché: riduce furto di sessione/cookie e downgrade.

- **Logging e audit**
  - Cosa fare: log strutturato per eventi auth (login, refresh, revoke, reset, mfa) con userId/ip/ua, senza token/codici; log rotation/retention.
  - Dove intervenire: endpoint `LoginEndpoints.cs`, `RefreshEndpoints.cs`, `Logout*`, `PasswordResetEndpoints.cs`, `ConfirmMfaEndpoints.cs`; setup Serilog sink/retention.
  - Perché: incident analysis senza leak di segreti.

- **Error handling coerente**
  - Cosa fare: garantire risposte uniformi senza enumeration (200/400/401/403/429/503 coerenti, nessun stacktrace in output).
  - Dove intervenire: confermare pattern già usato in `Login/Reset/ConfirmEmail`; aggiungere test di contract sugli status.
  - Perché: riduce info leak e comportamenti ambigui.

- **Patching dipendenze**
  - Cosa fare: abilitare aggiornamenti automatici (Dependabot/nuget audit), patch runtime; pipeline CI con restore/scan.
  - Dove intervenire: repo automation + process di rilascio.
  - Perché: chiude CVE note.

- **Config deploy**
  - Cosa fare: separare Dev/Staging/Prod; disabilitare debug/Swagger in prod o proteggerlo; options `ValidateOnStart`; health/ready dietro auth se esposte.
  - Dove intervenire: `appsettings.*`, pipeline deploy, hosting/proxy.
  - Perché: evitare exposure di endpoint di gestione e config errate.

### Verifiche rapide prima del go-live
- Smoke test HTTPS + cookie flags + header sicurezza.
- Test brute-force limit (login/reset) → ricevere 429/lockout.
- Rotazione segreti documentata e testata (JWT/pepper).
- Log controllati: nessun token/code MFA/refresh in chiaro.
- Backup/persistenza DataProtection keys configurata.

### Note
- Se qualche punto è fuori scope immediato, pianificare mitigazione temporanea (es. rate limit a livello di reverse proxy/WAF) e una data per chiuderlo.

---

## Punti di intervento rilevati nel codice

- **Rate limiting assente su login/register/refresh/confirm-email**  
  - Stato: throttle solo su `/password-reset/request` (`PasswordResetEndpoints.cs`), lockout login è “per utente” ma manca rate limit globale/IP.  
  - Azione: creare rate limiter condiviso (per IP e per endpoint critici) e applicarlo in `LoginEndpoints.cs`, `RefreshEndpoints.cs`, `RegisterEndpoints.cs`, `ConfirmEmailEndpoints.cs`. Aggiungere test che verificano 429/lockout.

- **Segreti ancora da spostare fuori config**  
  - Stato: `Jwt:SecretKey` e `TokenHashing:EmailConfirmPepper` leggono da configurazione; ValidateJwt blocca placeholder ma non forza secret store.  
  - Azione: prevedere binding da env/KeyVault e rimuovere i valori di esempio da `appsettings*.json`; documentare rotazione (chiave JWT + pepper) e testarla.

- **Audit logging parziale**  
  - Stato: log informativi presenti, ma non c’è un tracciamento strutturato uniforme per login/refresh/revoke/reset/mfa.  
  - Azione: aggiungere eventi strutturati (tipo, userId, ip, ua) nei relativi endpoint e verificare che non includano token/codici. Prevedere retention/rotation.

- **Header di sicurezza solo in non-Development**  
  - Stato: `UseSecurityHeaders()` applicato solo fuori dev; ok, ma serve check in deploy che HSTS/HTTPS siano obbligatori lato host/proxy.  
  - Azione: checklist di deploy (reverse proxy TLS + HSTS) e test automatizzati sugli header (curl/assert).

- **DataProtection key ring**  
  - Stato: chiavi persistite su file `.dpkeys` locale; warning “No XML encryptor configured” se non configurato l’encryptor.  
  - Azione: configurare protezione chiavi (CNG/DPAPI o storage cifrato) per ambienti prod; assicurare volume condiviso/backup per multi-instance.

- **Token in response/log solo in DEBUG**  
  - Stato: conferma email/reset restituiscono token in DEBUG e log sanitizzati; verificare che build/release non includa DEBUG e che le pipeline usino config corrette.

- **Cleanup/maintenance**  
  - Stato: cleanup per reset/session esiste, ma nessun monitoraggio/alert.  
  - Azione: aggiungere log/metriche sull’esito del cleanup e controlli periodici (job success/fail, contatori eliminati).

- **Error handling e contract**  
  - Stato: pattern uniforme su reset/login già presente, ma non ci sono test di contract sugli status per tutti gli endpoint.  
  - Azione: aggiungere test per garantire che errori non leakano stato account e che gli status code restino coerenti (400/401/403/429/503).

- **Swagger/debug surface**  
  - Stato: non gestito qui; rischia exposure se abilitato in prod.  
  - Azione: assicurarsi che Swagger/dev endpoints siano off o protetti in ambienti prod.
