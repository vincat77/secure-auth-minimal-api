# Piano: Reset password (forgot password)

## Obiettivo
Aggiungere un flusso di reset password per utenti non autenticati: richiesta token via email e conferma con nuova password. Integrare il flag `EmailConfirmation:Required` (es.: reset consentito solo per email confermate, oppure sempre?).

## Passi
1) Modellazione e storage (SQLite + Dapper coerente con stile repo esistenti):
   - Nuova tabella `password_resets` con colonne: id (PK string GUID), user_id, token, expires_at_utc, used_at_utc, client_ip, user_agent, created_at_utc.
   - Nuovo repository `PasswordResetRepository` con metodi:
     * `CreateAsync(PasswordReset reset, CancellationToken)`
     * `GetByTokenAsync(string token, CancellationToken)`
     * `MarkUsedAsync(string id, CancellationToken)`
     * `DeleteExpiredAsync(string nowIso, int batchSize, CancellationToken)` (per cleanup)
   - Modello `PasswordReset` in `Models/` per mapping Dapper.

2) Endpoint (minimal API allineato a stile esistente):
   - POST `/password-reset/request`
     * Input record `PasswordResetRequest { string? Email }`
     * Normalizza email (usar `NormalizeEmail` di EndpointUtilities).
     * Lookup utente per email_normalized (`UserRepository.GetByEmailAsync`).
     * Se utente non trovato, rispondere sempre 200 `{ ok = true }` (no leak).
     * Se `EmailConfirmation:Required` true e utente non confermato → 403 o 400 (`email_not_confirmed`) e audit facoltativo.
     * Genera token Guid "N" + expires (config `PasswordReset:Minutes`, default 30), salva in repo, logga.
     * Response 200 `{ ok = true, resetToken? (solo per test/dev), expiresAtUtc }` (in prod non restituire il token; qui possiamo restituirlo per test).
   - POST `/password-reset/confirm`
     * Input `PasswordResetConfirmRequest { string? Token, string? NewPassword, string? ConfirmPassword }`
     * Valida token non vuoto → se vuoto 400 invalid_input.
     * Carica reset via token, verifica non scaduto/unused, else 410/401.
     * Valida password con `AuthHelpers.ValidatePassword` usando config corrente.
     * Aggiorna password con `UserRepository.UpdatePasswordAsync`, revoca sessioni/refresh con `SessionRepository`/`RefreshTokenRepository` (se esistono helper; altrimenti nuovo metodo `RevokeAllForUserAsync` già presente in RefreshTokenRepository).
     * Marca reset usato (`MarkUsedAsync`).
     * Risposta 200 `{ ok = true }`.

3) Configurazione/comportamento:
   - Nuova sezione `PasswordReset` in appsettings con chiavi:
     * `Minutes` (default 30)
     * `IncludeTokenInResponse` (solo per dev/test; default false, in test possiamo abilitarlo via in-memory config)
     * `RequireConfirmedEmail` (default true; può riusare `EmailConfirmation:Required` se preferiamo non duplicare)
   - Nuovo parametro (es. `PasswordReset:AllowUnconfirmed`): se true consente il reset anche a utenti con email non confermata; se false permette solo utenti registrati e confermati.
   - Integrare con `EmailConfirmation:Required`: se `AllowUnconfirmed` è false, applicare il requisito di email confermata (default).

4) Test (xUnit, seguendo CreateFactory con extraConfig):
   - Flow completo: request (con IncludeTokenInResponse=true in config test) -> confirm con nuova password valida -> login con nuova password ok, vecchia 401; refresh/sessioni precedenti revocate.
   - Token scaduto: manipola DB per retrodatare expires e conferma → 410/401 nessun cambio password.
   - Token già usato: conferma due volte, seconda 401/410.
   - Email non trovata: request ritorna 200 ok true senza errore.
   - Email non confermata: con `AllowUnconfirmed=false` request risponde 403/400 e non crea token; con `AllowUnconfirmed=true` request ok e token creato.
   - Password policy fail: conferma con password debole → 400 password_policy_failed.

5) Documentazione:
   - Aggiornare `appsettings.guida.md` con sezione PasswordReset e opzioni.
   - Aggiungere breve nota in README o appsettings.guida su uso dei token (in prod via email).

6) Cleanup:
   - Estendere `ExpiredCleanupService` per includere `PasswordResetRepository.DeleteExpiredAsync(nowIso, batchSize)`.
   - Aggiornare `CleanupOptions` se serve un batch separato o riusare quello esistente.

7) Verifica finale:
   - Eseguire `dotnet test tests/SecureAuthMinimalApi.Tests/SecureAuthMinimalApi.Tests.csproj`.
   - Rigenerare tag `tools\\update-tags.ps1`.
