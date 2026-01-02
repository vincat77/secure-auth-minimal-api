# Piano dettagliato: MFA a due step (challenge) + aggiornamento WinForms

Obiettivo: separare il login in due fasi quando l’utente ha MFA attivo:
1) Fase 1: verifica password → se MFA attivo, risponde `mfa_required` con un `challengeId` (sessione provvisoria o stato in DB); non emette sessione finale né access token.
2) Fase 2: conferma TOTP (`POST /login/confirm-mfa`) con `challengeId` + `totpCode` → crea sessione JWT/cookie e CSRF.

## Contesto attuale
- `POST /login` (src/SecureAuthMinimalApi/Program.cs): login one-step, richiede TOTP nel body se presente `TotpSecret`; in caso di TOTP mancante/errato → 401 e audit outcome `mfa_required` o `invalid_totp`. Crea subito sessione, JWT, CSRF, refresh/device.
- TOTP: segreti cifrati con DataProtection (`TotpSecretProtector`, UserRepository li cifrano a riposo).
- Test attuali: coprono flusso one-step con TOTP (no challenge).
- WinForms: un unico bottone Login che invia password+totp insieme; nessuna gestione di challenge.

## File da modificare
- `src/SecureAuthMinimalApi/Program.cs`: aggiungere logica challenge e nuovo endpoint di conferma.
- `src/SecureAuthMinimalApi/Data`: nuovo repository o estensione per persistente challenge MFA (se si vuole stato server-side).
  - Opzione A: tabella `mfa_challenges` (challenge_id, user_id, created_at_utc, expires_at_utc, used_at_utc, user_agent, client_ip).
  - Opzione B: challenge JWT signed (stateless), ma più complesso per revoca; preferire tabella semplice SQLite.
- `src/SecureAuthMinimalApi/Data/DbInitializer.cs`: DDL per tabella `mfa_challenges`.
- `src/SecureAuthMinimalApi/Models`: record per il challenge (es. `MfaChallenge`).
- `tests/SecureAuthMinimalApi.Tests/ApiTests.cs`: nuovi test end-to-end per flusso two-step.
- WinForms:
  - `clients/WinFormsClient/MainForm.cs`: aggiungere UI e flusso due-step (bottoni separati: “Login (password)”, “Conferma MFA”).
  - Eventuali controlli/label per mostrare `challengeId`.

## Modifiche API (Program.cs)
1) `POST /login`:
   - Se utente senza TOTP: comportarsi come ora (sessione piena).
   - Se utente con TOTP:
     - Verifica password.
     - Crea challenge (GUID), salva in DB con scadenza breve (es. 5–10 minuti), user_agent e client_ip.
     - Risponde `401` o `403` con payload `{ ok=false, error="mfa_required", challengeId="..." }` (status 401 consigliato).
     - Non crea sessione JWT né refresh token.
   - Nessun fallback one-step per utenti MFA: la sessione viene emessa solo dopo il secondo step.
   - Rischi/impatti:
     - I client non aggiornati per utenti con TOTP riceveranno `mfa_required` e non completeranno il login finché non implementano il secondo step.
     - Aumento chiamate: da 1 a 2 richieste per login MFA; valutare performance/lockout (usare lo stesso throttle del login?).
     - Necessità di gestire expiry del challenge: se troppo breve, user experience peggiore; se troppo lungo, finestra d’attacco più ampia.
2) Nuovo endpoint `POST /login/confirm-mfa`:
   - Input: `challengeId`, `totpCode`.
   - Carica challenge valido/non usato/non scaduto; confronta UA e IP se si vuole binding.
   - Verifica TOTP con il segreto utente.
   - Marca challenge come usato/consumato.
   - Crea sessione come flusso attuale (JWT cookie, CSRF, remember/refresh/device).
3) Challenge cleanup:
   - Opzionale job/manuale per eliminare challenge scaduti; non essenziale in prima iterazione.

## Modifiche DB (DbInitializer.cs)
- Aggiungere tabella `mfa_challenges`:
  ```
  CREATE TABLE IF NOT EXISTS mfa_challenges (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    created_at_utc TEXT NOT NULL,
    expires_at_utc TEXT NOT NULL,
    used_at_utc TEXT NULL,
    user_agent TEXT NULL,
    client_ip TEXT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_mfa_challenges_user ON mfa_challenges(user_id);
  ```
  - Eventuale indice su `expires_at_utc` per cleanup.
- Compatibilità e rischi:
  - Non tocchiamo le tabelle esistenti (users, user_sessions, refresh_tokens). L’aggiunta di `mfa_challenges` è additive, quindi non rompe DB già creati.
  - Inserire in `DbInitializer` l’EnsureColumn/DDL per creare la tabella se manca; non servono migrazioni destructive.
  - Cleanup: senza job di pulizia, la tabella può crescere; primo passo accettabile, ma da monitorare.
  - Se si usa binding UA/IP nel challenge, lo storage `user_agent`/`client_ip` non contiene PII sensibili aggiuntive rispetto ai log già presenti.

## Configurazioni (appsettings.json)
- Aggiungere sezione `Mfa` con:
  - `ChallengeMinutes` (int, default es. 10) durata del challenge.
  - `RequireUaMatch` (bool, default true): enforce UA del challenge.
  - `RequireIpMatch` (bool, default false/true a scelta): binding IP (potrebbe causare falsi negativi).
  - (Opzionale) `MaxAttemptsPerChallenge` (int): limite di tentativi TOTP per challenge; se superato, invalidare il challenge.
- Validare e applicare i default in Program.cs; fail-fast se `ChallengeMinutes` <= 0.

## Modello/Repository
- Nuova classe `MfaChallenge` (Id, UserId, CreatedAtUtc, ExpiresAtUtc, UsedAtUtc, UserAgent, ClientIp).
- Repository con metodi:
  - `CreateAsync(challenge)`
  - `GetValidAsync(id, now, ua, ip)` (verifica scadenza e non usato; opzionale match UA/IP)
  - `MarkUsedAsync(id, now)`
  - Considerare `MaxAttemptsPerChallenge` (se configurato) per limitare i tentativi TOTP sul singolo challenge.

## Test xUnit (ApiTests)
- Test nuovi da aggiungere:
  - Login utente con TOTP → risposta `mfa_required` con `challengeId`, nessun cookie sessione/refresh emesso.
  - Confirm-mfa con codice corretto → 200 OK, emette sessione/CSRF/refresh/device come oggi.
  - Confirm-mfa con codice errato → 401.
  - Confirm-mfa con challenge scaduto/usato → 401/410.
  - Confirm-mfa con UA/IP diversa (se binding attivo) → 401.
  - Utente senza TOTP → login resta one-step invariato.
- Test esistenti da adattare/copiare per nuovo flusso:
  - `Totp_setup_and_login_success`: diventa two-step (login → mfa_required → confirm-mfa).
  - `Totp_disable_allows_login_without_code`: dopo disable, login torna one-step; prima del disable, aspettarsi mfa_required.
  - Test remember/device/refresh per utenti con MFA: rifare il flusso (login → mfa_required → confirm-mfa con RememberMe=true) e verificare cookie access/refresh/device e rotazione.
  - Helper `LoginAndGetSessionAsync`: aggiornare per gestire eventuale `mfa_required` (può accettare flag/parametro per eseguire automaticamente la conferma con TOTP).
  - Test di audit (outcome `mfa_required`, `invalid_totp`) da aggiornare con il nuovo endpoint, verificando che gli audit siano ancora scritti correttamente.
  - Aggiungere un test che il secondo step emetta Set-Cookie refresh/device solo dopo confirm-mfa (non nel primo step).
  - Aggiungere test per challenge scaduto (cleanup) e per `AllowLegacyOneStep=true/false` (comportamento diverso).

## WinForms (MainForm.cs)
- Stato/UI:
  - Aggiungere una label “Challenge MFA” e una textbox (read-only) per mostrare/stoccare il `challengeId` ricevuto.
  - Aggiungere un bottone “Login (password)” che invia solo username/password (senza totp) a `/login`.
  - Aggiungere un bottone “Conferma MFA” che invia `challengeId` + `totpCode` a `/login/confirm-mfa`.
  - Riutilizzare la textbox TOTP esistente per inserire il codice nella seconda fase.
  - Mostrare stato MFA corrente: “MFA richiesta, inserisci TOTP”, “MFA confermata”, “Challenge scaduto/non valido”.
- Flusso:
  - Primo step: chiamare `/login` con payload senza totp; se risposta `mfa_required`, salvare `challengeId`, mostrare messaggio, NON impostare csrf/sessione, non aggiornare sessionCard.
  - Secondo step: chiamare `/login/confirm-mfa` con `challengeId` + `totpCode`; se ok, aggiornare csrf, sessione, card, countdown, device info, remember label.
  - In caso di errore (401/410), mostrare messaggio e svuotare `challengeId` (chiedere nuovo login password).
  - Se l’utente non ha MFA attivo, il bottone “Login (password)” può ancora inviare totp vuota e ottenere sessione diretta; mantenere compatibilità.
  - Se il server risponde `mfa_required` (legacy disabilitato), la UI deve disabilitare il flusso one-step e guidare l’utente al secondo step.
- Log/feedback:
  - Log eventi chiari in italiano: es. “MFA richiesta, challenge=...”, “MFA confermata”, “Challenge non valido/scaduto”, “Codice TOTP errato”.
  - Pannello device/alert: in seconda fase, dopo conferma, aggiornare come in login normale (remember/device).
  - Output/Console: indicare lo stato in modo coerente (senza dati sensibili).

## Considerazioni di compatibilità
- API:
  - Utenti senza TOTP: `/login` continua a restituire sessione completa (compatibile con client attuali).
  - Utenti con TOTP: solo two-step, nessun fallback one-step; i client non aggiornati falliranno con `mfa_required` finché non implementano il secondo step.
- WinForms:
  - Va aggiornato per supportare due bottoni/fasi. Finché il server accetta ancora il one-step, rimane compatibile; se si forza il two-step, la WinForms attuale non funzionerà con utenti MFA finché non aggiornata.
  - Per evitare rotture immediate, si può implementare il two-step in WinForms mantenendo la chiamata one-step solo se l’utente non ha TOTP (o come fallback se il server risponde 401 mfa_required, innescare la UI di challenge).
- Test e client Postman:
  - Aggiornare/aggiungere casi two-step; mantenere i test one-step per utenti senza TOTP.
  - Eventuali collection Postman devono includere il flusso a due step e, se presente, il fallback one-step di transizione.

## Rischi e punti da chiarire
- Throttle/audit: decidere se il secondo step usa lo stesso throttle del login o un contatore separato; loggare outcome `mfa_required`, `invalid_totp`, `mfa_confirmed` anche su `/login/confirm-mfa`.
- CSRF: `/login/confirm-mfa` è pre-sessione → nessun CSRF token necessario (va documentato/implementato chiaramente).
- Cleanup: tabella challenge cresce senza job; da pianificare un cleanup (anche manuale) e test di scadenza.
- Config validation: `ChallengeMinutes<=0` deve fare fail-fast; se `RequireIpMatch=true` ma manca IP (dev), gestire fallback/warning.
- Compat test: elencare i test da aggiornare (vedi sopra) e aspettarsi esiti `mfa_required` nei flussi MFA.
- Remember/Device: i cookie di refresh/device devono essere emessi solo al secondo step; nessuna emissione nel primo step.
- Fallback legacy: chiarire se `AllowLegacyOneStep` resta attivo e per quanto; se disabilitato, i client non aggiornati falliranno il login MFA.

## Sequenza di sviluppo consigliata
1) **Test prima** (approccio TDD light):
   - Scrivere i nuovi test xUnit che descrivono il comportamento atteso (mfa_required, confirm-mfa ok/ko, fallback utenti senza TOTP, remember/device nel secondo step). In questa fase falliranno (red). Esempio: `Totp_setup_and_login_success` ora aspetta 401 mfa_required e fallisce.
   - Test già aggiunti (stato: ROSSI finché non si implementa): `Totp_setup_and_login_success`, `Totp_challenge_rejects_wrong_code`, `Totp_challenge_requires_confirm_step_for_cookies`, `Totp_challenge_expired_or_used_returns_unauthorized`, `Totp_challenge_rejects_different_user_agent`, `Totp_challenge_max_attempts_invalidates_challenge`, `Totp_challenge_rejects_different_ip_when_required`, mentre `Login_without_totp_remains_one_step` resta verde.
2) DB + modello + repo challenge.
3) Endpoint `/login` aggiornato (two-step per utenti MFA) con eventuale `AllowLegacyOneStep` per compat.
4) Endpoint `/login/confirm-mfa`.
5) Aggiornare i test esistenti e farli passare (green).
6) WinForms UI flusso due-step.
7) Cleanup e, se necessario, job di pulizia challenge scaduti.

## Micro-step e checklist per file
- **DbInitializer.cs**
  - [ ] Aggiungi tabella `mfa_challenges` con campi id, user_id, created_at_utc, expires_at_utc, used_at_utc, user_agent, client_ip.
  - [ ] Indici: per user_id (e opzionale expires_at_utc per cleanup).
  - [ ] Verifica che la creazione sia additive (non modifica tabelle esistenti).

- **Modello/Repository**
  - [ ] Nuovo modello `MfaChallenge` con proprietà Id, UserId, CreatedAtUtc, ExpiresAtUtc, UsedAtUtc, UserAgent, ClientIp, AttemptCount (se si usa MaxAttempts).
  - [ ] Nuovo repo `MfaChallengeRepository` con metodi CreateAsync, GetValidAsync (scadenza, non usato, match UA/IP opzionali), MarkUsedAsync, IncrementAttemptAsync/MaxAttempts.

- **Program.cs (API)**
  - [ ] Config Mfa: ChallengeMinutes (>=1, default 10), RequireUaMatch=true, RequireIpMatch=false, MaxAttemptsPerChallenge=5.
  - [ ] /login:
    - Se TOTP assente → flusso attuale.
    - Se TOTP presente → verifica password, crea challenge (UA/IP), risponde 401 con error=mfa_required + challengeId. Nessun cookie/sessione/refresh/device emesso.
  - [ ] /login/confirm-mfa:
    - Input: challengeId, totpCode.
    - Verifica challenge (scadenza, non usato, UA/IP se richiesto, max tentativi).
    - Verifica TOTP; se ok → MarkUsed + crea sessione (access JWT + CSRF + refresh/device come oggi).
    - Se TOTP errato → incrementa tentativi, opzionale invalidazione se supera MaxAttempts.
    - Nessun CSRF richiesto (pre-sessione).
  - [ ] Audit: registra mfa_required, invalid_totp, mfa_confirmed.
  - [ ] Cookie emissione: solo in /confirm-mfa (non in /login).
  - [ ] Cleanup best-effort: DELETE challenge scaduti (es. in /login o /confirm).

- **Test (tests/SecureAuthMinimalApi.Tests/ApiTests.cs)**
  - [ ] Nuovi test: mfa_required (nessun cookie), confirm-mfa ok (cookie access/refresh/device), confirm-mfa errato (401), challenge scaduto/usato (410/401), UA/IP mismatch (se RequireIpMatch attivo), MaxAttempts (se configurato).
  - [ ] Aggiorna `Totp_setup_and_login_success`, `Totp_disable_allows_login_without_code`, test remember/device/refresh per flusso two-step.
  - [ ] Helper LoginAndGetSessionAsync: gestire mfa_required (param per auto-confirm).
  - [ ] Test che il primo step non emette cookie; il secondo sì.

- **WinForms (MainForm.cs)**
  - [ ] UI: label/textbox challengeId (read-only), bottoni separati “Login (password)” e “Conferma MFA”.
  - [ ] Flusso: primo step salva challenge, mostra stato; secondo step invia totp+challenge, aggiorna sessione/card/countdown/device.
  - [ ] Gestione errori: 401/410/invalid_totp → messaggi chiari, reset challenge.
  - [ ] Log eventi in italiano con stati MFA.

- **Postman/Collection (se usata)**
  - [ ] Aggiungi chiamate /login (mfa_required) e /login/confirm-mfa, con variabili per challengeId e totp.

- **Pulizia/Maintenance**
  - [ ] Cleanup challenge scaduti (anche manuale) per evitare crescita DB.
  - [ ] Non loggare challengeId in chiaro se non necessario (eventuale mascheramento).
