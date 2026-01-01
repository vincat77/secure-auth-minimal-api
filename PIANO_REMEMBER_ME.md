# Piano dettagliato: Remember Me (refresh cookie persistente)

Obiettivo: introdurre “Ricordami” con refresh cookie persistente, mantenendo l’access token breve e HttpOnly, con rotazione e revoca server-side. Coprire API, schema, sicurezza, test e UI WinForms.

## Assunzioni e principi
- Access token (JWT) resta breve (es. 30–60 min) su cookie `access_token` HttpOnly.
- Refresh/remember è un cookie separato (`refresh_token`), HttpOnly, Secure, SameSite=Strict (o Lax se serve navigazione interdominio), durata limitata (7–30 giorni), mai in LocalStorage.
- Rotazione ad ogni uso: il refresh usato viene invalidato, se ne emette uno nuovo e lo stato è in DB (no stateless).
- Binding dispositivo: almeno User-Agent; opzionale IP (/24) per ridurre replay cross-device.
- Logout revoca sessione e refresh corrente; opzione “logout all devices” per revocare tutti i refresh dell’utente.
- MFA e throttle restano invariati; remember me non bypassa MFA se richiesto.
- DB è l’unica fonte di verità per i refresh (token random, non JWT).

## Modifiche API (server)
1) Schema dati
   - Tabella `refresh_tokens`:
     - id (PK GUID), user_id (FK), session_id (FK opzionale), token (random 256 bit Base64Url, UNIQUE), created_at_utc TEXT, expires_at_utc TEXT, revoked_at_utc TEXT, user_agent TEXT, client_ip TEXT, rotation_parent_id TEXT (nullable), rotation_reason TEXT (es. rotated/logout/compromised).
   - Indici: UNIQUE(token); INDEX(user_id); INDEX(session_id).
   - Repo: Create, GetByToken, RevokeById, RevokeAllForUser, Rotate(parent→child).

2) DTO e configurazione
   - `LoginRequest`: aggiungere `RememberMe` bool.
   - Config `RememberMe`:
     - `RememberMe:Days` (default 14)
     - `RememberMe:SameSite` (Strict|Lax, default Strict)
     - `RememberMe:CookieName` (default `refresh_token`)
     - `RememberMe:Path` (default `/refresh`)
   - Access token resta governato da `Jwt:AccessTokenMinutes`.

3) Login flow
   - Se login ok e `RememberMe=true`:
     - Genera refresh random 32 byte → Base64Url; expires = now + Days.
     - Persisti con userId, sessionId (se si riusa la stessa), UA, IP, rotation_parent_id null.
     - Set-Cookie refresh HttpOnly, Secure (forzato fuori Dev), SameSite da config, Path da config, Max-Age = durata refresh.
     - Risposta login: flag `rememberIssued=true` e opzionale `refreshExpiresAtUtc`.
   - Se `RememberMe=false`: nessun refresh emesso.

4) Endpoint /refresh
   - `POST /refresh` (no body): legge `refresh_token` dal cookie.
   - Valida: esiste, non revocato, non scaduto, UA match (IP opzionale).
   - Rotazione: genera nuovo refresh, set rotation_parent_id al vecchio, marca il vecchio revoked_at_utc/rotation_reason=”rotated”.
   - Access token: opzione B (consigliata per minimal change) rinnova la stessa sessione aggiornando expires/CSRF; opzione A crea nuova sessione id (più sicura).
   - Risposta: nuovo `access_token` cookie (breve) + nuovo `refresh_token` cookie; nuovo CSRF se serve.

5) Logout
   - `POST /logout`: revoca sessione e, se presente cookie refresh, revoca quel token in DB (rotation_reason=”logout”).
   - Opzionale endpoint “/logout-all” per revocare tutti i refresh di un user.

6) Sicurezza e policy
   - Token refresh random, non JWT; no reuse dopo rotazione.
   - SameSite Strict di default; Lax solo se richiesto.
   - Binding UA obbligatorio; IP opzionale configurabile.
   - Scadenza hard: nessun “sliding” oltre il max configurato senza rotazione.
   - `Cookie:RequireSecure` sempre true fuori Dev (già presente).

7) Test xUnit da aggiungere
   - Login remember=true → Set-Cookie refresh presente, Max-Age ≈ config, flag rememberIssued in body.
   - Refresh valido → nuovo access_token e nuovo refresh; vecchio refresh marcato revoked.
   - Refresh revocato/scaduto → 401/403.
   - Logout → refresh non più usabile (refresh call → 401/403).
   - UA mismatch → 401/403.
   - Config RememberMe:Days applicata (verifica Max-Age).
   - Opzionale: logout-all revoca tutti i refresh dell’utente.

## Modifiche WinForms
1) UI
   - Checkbox “Ricordami” nel form di login.
   - Log/label che indica se il refresh è stato emesso (leggendo header Set-Cookie o flag risposta).
   - Pulsante “Refresh” (opzionale) per chiamare `/refresh` e aggiornare sessione/CSRF (test manuale).

2) HTTP
   - `CookieContainer` gestisce sia access che refresh in automatico.
   - `/refresh` non richiede body né header speciali (solo cookie).

3) Countdown
   - Opzionale: se API restituisce `refreshExpiresAtUtc`, mostrarlo con countdown/progress simile alla sessione.

## Passi incrementali proposti
1) **Schema & modello (atomico, no side-effect runtime)**
   - Aggiungere tabella `refresh_tokens` (DDL) + indici + modello POCO.
   - Nessun codice runtime modificato; eseguire xUnit per garantire nessuna regressione.
2) **Repository isolato**
   - Implementare repo con metodi Create/GetByToken/Revoke/Rotate, senza ancora aggancio al login.
   - Aggiungere test unit/integration per il repo (CRUD/rotazione) senza toccare i flow esistenti.
3) **Config & DTO (wire-only)**
   - Estendere `LoginRequest` con `RememberMe`; aggiungere config `RememberMe:*` con default.
   - Non cambiare comportamento login; xUnit per verificare backward compatibility (login senza remember resta invariato).
4) **Emissione refresh opzionale**
   - In login, se `RememberMe=true`, creare e salvare refresh + Set-Cookie; se false, comportamento invariato.
   - Aggiungere test per login remember=true (Set-Cookie presente, Max-Age da config) e remember=false (nessun refresh).
5) **Endpoint /refresh isolato**
   - Implementare `/refresh` che valida/ruota refresh e rilascia nuovo access+refresh; non cambiare altri endpoint.
   - Test per refresh valido, revocato, scaduto, UA mismatch.
6) **Logout con revoca refresh**
   - Estendere logout per revocare il refresh corrente (se presente); mantenere compatibilità esistente.
   - Test: dopo logout il refresh non funziona più.
7) **Opzionale: logout-all**
   - Endpoint separato che revoca tutti i refresh dell’utente; test dedicati.
8) **UI WinForms (opt-in)**
   - Checkbox “Ricordami” nel login; log flag refresh emesso; (opzionale) pulsante “Refresh”.
   - Test manuali + build WinForms; xUnit non impattati.
