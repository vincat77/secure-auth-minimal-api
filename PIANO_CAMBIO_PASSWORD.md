# Piano: cambio password utente loggato

Obiettivo: permettere a un utente gia autenticato di cambiare la propria password in modo sicuro, rispettando le policy esistenti e chiudendo le sessioni vecchie (rotazione sessione + refresh).

## Contesto attuale
- Autenticazione cookie+JWT con sessione server-side e CSRF header; logout e revoca gia presenti.
- Password create in registrazione con `AuthHelpers.ValidatePassword(...)` e `PasswordHasher.Hash(...)` (siamo gia compatibili con una policy minima configurabile).
- UserRepository gestisce l update di password e email confermata; non esiste endpoint di cambio password.
- WinForms Client ha form di login/registrazione; nessuna UI per cambio password.

## Requisiti funzionali
- Endpoint protetto (richiede sessione valida e CSRF): input `currentPassword`, `newPassword`, `confirmPassword` (o `repeatPassword`); errore se i due nuovi valori non coincidono.
- Validare la password corrente (hash), applicare la stessa policy di registrazione al nuovo valore (riuso `AuthHelpers.ValidatePassword` con config attuale).
- Rifiutare nuove password uguali alla precedente; opzionale controllo su riuso storico non gestito ora ma previsto per evoluzione (`last_password_change_utc` + tabella history).
- In caso di successo, ruotare la sessione corrente e invalidare le altre sessioni/refresh token dell utente (logout degli altri device).
- Audit/log di esito (success/failure) e motivi (password errata, policy, CSRF mancante, mismatch conferma); log info su success, warn su failure.
- Rate limiting: riutilizzare eventuale throttle di login se presente o aggiungere contatore sul cambio password per evitare bruteforce del current password.

## API e logica applicativa
1) Aggiungere endpoint `POST /me/password` (o `POST /account/password`) in `Program.cs`, protetto da cookie JWT + CSRF.
2) Passi:
   - Recupera userId da sessione, carica utente da UserRepository; se non trovato -> 401.
   - Verifica `currentPassword` con `PasswordHasher.Verify(...)`; se fallisce, log warn e risposta 400 con `error="invalid_current_password"`.
   - Se `newPassword` != `confirmPassword`, 400 con `error="password_mismatch"`.
   - Valida `newPassword` con `AuthHelpers.ValidatePassword(...)`; se ci sono errori, 400 con elenco.
   - Rifiuta se `newPassword` uguale alla vecchia (prima del hash).
   - Aggiorna hash nel DB via UserRepository (nuovo metodo dedicato `UpdatePasswordAsync(userId, hash)`).
   - Revoca refresh token esistenti e sessioni attive (salvo quella corrente) per forzare nuovo login sugli altri device; se la tabella refresh e disponibile usare batch update.
   - Ruota la sessione corrente: genera nuovo JWT/cookie, nuovo CSRF, aggiorna record sessione (preferibile nuova sessionId per clean slate e jti/iat fresh).
   - Audit: log success e outcome; considerare audit entry `password_change`.
3) Risposta: `{ ok: true }` e nuovi header/cookie se la sessione viene ruotata; eventuali errori restituiscono payload strutturato `{ ok: false, error, errors? }`.

## Piano operativo (passi atomici)
1) Backend: contratti
   - Aggiungi record/DTO `ChangePasswordRequest` e risposta `{ ok, error?, errors? }`.
2) Backend: endpoint
   - In Program.cs crea `POST /me/password` protetto da cookie/CSRF.
   - Recupera utente da sessione; se mancante 401.
   - Validazioni: current hash, match new/confirm, policy, new != old; return 400 con errori dettagliati.
3) Backend: repo e sessioni
   - Aggiungi `UpdatePasswordAsync(userId, newHash)` in UserRepository.
   - Aggiungi metodi per revocare refresh/sessioni di un utente (esclusa la corrente) e usali nel flusso.
   - Ruota sessione corrente generando nuovo JWT/cookie + CSRF e aggiornando record sessione.
4) Backend: audit/log
   - Log warn su failure (password errata/policy/mismatch), info su success con outcome `password_change`.
5) Client WinForms: UI
   - Aggiungi sezione cambio password con 3 campi + bottone, visibile solo se autenticato.
6) Client WinForms: handler
   - Implementa chiamata POST con CSRF, gestisci errori server/policy, messaggi UI, reset campi al successo.
7) Testing API
   - E2E: success con rotazione sessione/CSRF; current errata; mismatch; policy; csrf mancante; vecchia sessione/refresh revocati.
8) Testing Unit
   - UserRepository update hash (SQLite in-memory); funzione di rotazione sessione (nuovo jti/csrf).
9) Testing WinFormsClient.Tests
   - Handler HTTP con mock: success/failure, header CSRF, reset campi, gating autenticazione, errori rete.
10) Documentazione
    - Aggiorna README/PIANO e sample Postman/WinForms per nuovo endpoint e flusso.

## Persistenza/DB
- Nessuna migration necessaria per la prima iterazione; usare le colonne esistenti.
- Opzionale (seconda iterazione): aggiungere `last_password_change_utc` su `users` per auditing e invalidazione automatica di sessioni antecedenti.

## Client WinForms
- Aggiungere sezione "Cambio password" visibile solo quando autenticato:
  - Campi: password corrente, nuova, conferma; bottone "Cambia password".
  - Chiama `POST /me/password` con header CSRF e cookie esistente; gestisce errori di policy e messaggi UI.
  - Se il server ruota la sessione, aggiornare device/session info e stato UI (eventuale refresh id_token/avatar non necessario).
  - Aggiungere loader e reset dei campi al successo; se logout forzato, mostrare stato disconnesso.

## Testing
- API: test end-to-end in `tests/SecureAuthMinimalApi.Tests/ApiTests.cs` o file dedicato:
  - cambio password con sessione valida -> 200, login con vecchia password fallisce, con nuova riuscito (verifica anche che sessione vecchia venga rifiutata se si usa lo stesso cookie).
  - password corrente sbagliata -> 400 con `error="invalid_current_password"`.
  - violazione policy nuova password -> 400 con elenco errori e nessun cambio di hash.
  - mismatch conferma -> 400 con `error="password_mismatch"`.
  - CSRF mancante -> 403 (gia coperto da middleware).
  - verifica che le sessioni/refresh precedenti siano revocate (login vecchio cookie deve fallire) e che la sessione corrente sia ruotata con nuovo csrf/jti.
- xUnit dettagliato:
  - Test fixture con helper `LoginAndGetSessionAsync` per riusare setup cookie/csrf.
  - Test parametrico per policy (es: password senza maiuscola) usando `MemberData`.
  - Test di concorrenza: due richieste cambio password simultanee -> una sola deve avere successo, l altra fallire per hash aggiornato.
  - Test su rotazione sessione: dopo cambio password, endpoint protetto con vecchio CSRF deve fallire; con nuovo CSRF deve passare.
  - Test su refresh token: dopo cambio password, usare vecchio refresh deve fallire (se implementiamo revoke refresh).
  - Test su audit/log: verificare che venga loggato `password_change` o codice risultato; usare logger fake/spia.
  - Test negative su input nullo/vuoto e trimming: `currentPassword` mancante -> 400; `newPassword` whitespace -> 400 policy.
  - Test su enforcement lunghezza minima configurata: override configurazione e verificare fail su password corta.
  - Test su invarianti DB: dopo cambio password, l hash memorizzato e diverso dal precedente e non e vuoto; transazione atomica (nessuna sessione revocata se l update fallisce).
  - Test su limite tentativi/rate limit se introdotto: dopo N failure consecutive su current password, successivo tentativo -> 429/lockout simulato.
- Unit: test su UserRepository update (mock DB o in-memory SQLite) e sulla funzione che ruota sessione generando nuovo JWT/CSRF.
- WinForms (WinFormsClient.Tests):
  - Handler cambio password: percorsi success/failure con HttpClient mock; verifica payload inviato (current/new/confirm), gestione errori policy e invalid_current_password.
  - Reset UI: al successo i textbox vengono svuotati e lo stato resta autenticato; al failure lo stato non cambia.
  - CSRF/header: verifica che venga incluso l header X-CSRF-Token gia presente nello stato sessione client.
  - Gestione network error: mostra messaggio errore e non resetta campi.
  - Accessibilita base: i controlli cambio password sono abilitati solo quando autenticato.

## Rollout e retrocompatibilita
- Nessuna retrocompatibilita richiesta: i client devono aggiornarsi al nuovo endpoint e alla UI di cambio password; eventuali versioni precedenti potranno fallire sui flussi protetti finche non aggiornate.
- Documentare il nuovo flusso in README/PIANO e nei sample Postman/WinForms; rimuovere eventuali riferimenti a flussi precedenti.
