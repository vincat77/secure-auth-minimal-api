# Piano: Reset password (forgot password)

## Obiettivo
Aggiungere un flusso di reset password per utenti non autenticati: richiesta token via email e conferma con nuova password. Integrare il flag `EmailConfirmation:Required` (es.: reset consentito solo per email confermate, oppure sempre?).

## Stato attuale (codice)
- Non esistono tabella/reset repo/modello per `password_resets`.
- Nessun endpoint `/password-reset/request` o `/password-reset/confirm`.
- Nessuna sezione `PasswordReset` in appsettings/Program.
- Nessun `IEmailService`; solo logging Serilog.
- Cleanup gestisce session/refresh/mfa, ma non token di reset (che non esistono).
- Utility riutilizzabili: `NormalizeEmail`, `AuthHelpers.ValidatePassword`, hashing password, `SessionRepository.RevokeAllForUserAsync`, `RefreshTokenRepository.RevokeAllForUserAsync`.

## Passi
1) Modellazione e storage (SQLite + Dapper coerente con stile repo esistenti):
   - Nuova tabella `password_resets` con colonne: id (PK string GUID), user_id, token_hash (non il token in chiaro), expires_at_utc, used_at_utc, created_at_utc, client_ip, user_agent.
   - Indici/constraints: `token_hash` unique; indice su `expires_at_utc` per cleanup; (facoltativo) logica nel repo per avere 1 reset attivo per user (invalidare i precedenti).
   - Nuovo repository `PasswordResetRepository` con metodi:
     * `CreateAsync(PasswordReset reset, CancellationToken)` (invalida eventuali precedenti attivi dello stesso user)
     * `GetByTokenAsync(string token, CancellationToken)` (confronto hash constant-time)
     * `MarkUsedAsync(string id, CancellationToken)`
     * `DeleteExpiredAsync(string nowIso, int batchSize, CancellationToken)` (per cleanup)
   - Modello `PasswordReset` in `Models/` per mapping Dapper.

2) Endpoint (minimal API allineato a stile esistente):
   - POST `/password-reset/request`
     * Input record `PasswordResetRequest { string? Email }`
     * Normalizza email (usar `NormalizeEmail` di EndpointUtilities).
     * Lookup utente per email_normalized (`UserRepository.GetByEmailAsync`).
     * Risposta sempre 200 `{ ok = true }` per evitare enumeration (anche se email non trovata o non confermata).
     * Richiede email confermata: se l'utente non ha `EmailConfirmed=true`, non crea token (opzionale: trigger resend conferma).
     * Genera token random (32+ byte RNG, base64url), salva solo hash, setta expires (config `PasswordReset:Minutes`, default 30), invalida reset precedenti per lo stesso user, logga senza segreti.
     * Response 200; l'eventuale `resetToken` solo in dev/test con guardrail (env check) se serve ai test.
   - POST `/password-reset/confirm`
     * Input `PasswordResetConfirmRequest { string? Token, string? NewPassword, string? ConfirmPassword }`
     * Valida token non vuoto → se vuoto 400 invalid_input.
     * Carica reset via token hash, verifica non scaduto/unused, else 400 `invalid_token` (uniforme, no 401/410).
     * Valida password con `AuthHelpers.ValidatePassword` usando config corrente.
     * Transazione: update password, revoca sessioni/refresh (RevokeAllForUserAsync), mark used.
     * Risposta 200 `{ ok = true }`.

3) Configurazione/comportamento:
   - Nuova sezione `PasswordReset` in appsettings con chiavi:
     * `Minutes` (default 30)
     * `IncludeTokenInResponse` (solo per dev/test; default false, in test possiamo abilitarlo via in-memory config)
   - Comportamento: il reset è consentito solo se l'email è confermata, a prescindere da `EmailConfirmation:Required` per il login.

4) Test (xUnit, seguendo CreateFactory con extraConfig):
   - Flow completo: request (con IncludeTokenInResponse=true in config test) -> confirm con nuova password valida -> login con nuova password ok, vecchia 401; refresh/sessioni precedenti revocate.
   - Token scaduto: manipola DB per retrodatare expires e conferma → 400 invalid_token, nessun cambio password.
   - Token già usato: conferma due volte, seconda 400 invalid_token.
   - Email non trovata: request ritorna 200 ok true senza errore.
   - Email non confermata: request torna 200 ma senza creare token; opzionale resend conferma.
   - Password policy fail: conferma con password debole → 400 password_policy_failed.
   - Rate limit/abuse: prevedere limitazioni su richieste di reset per IP/email e auditing per tentativi falliti (non implementato inizialmente ma raccomandato).
   - Resend token conferma: decidere se e quando inviare automaticamente un nuovo token di conferma quando il reset è rifiutato per email_non_confirmed.
   - Correzione email: per utenti non confermati con email errata, considerare un flow autenticato di cambio email prima del reset.
   - Correzione email (stato attuale: solo resend token): manca un flusso di cambio email per utenti non confermati; opzione futura: endpoint autenticato per aggiornare Email/EmailNormalized e rigenerare token.
   - Revoca: verificare che il reset revochi refresh/sessioni attive.
   - Rate limit/resend: applicare limiti ai resend/reset per evitare flood verso l'email.
   - Token reuse: assicurarsi che un token marcato usato/scaduto non possa essere riutilizzato.
   - Cleanup: garantire che i token scaduti vengano rimossi regolarmente per non accumularsi.
   - Token invalidato da nuova richiesta: request #1 crea token1, request #2 invalida token1 (used_at_utc settato), confirm token1 fallisce, token2 funziona.
   - RequireConfirmed=false: utente non confermato può ottenere token e completare reset.
   - Account locked/deleted (stato attuale: schema e blocchi già in codice; mancano test dedicati):
     * Schema: `users` ha `is_locked` (INT) e `deleted_at_utc` (TEXT), mappati in `User` e nelle query `UserRepository`.
     * Endpoint /password-reset/request: se locked o deleted → log info e risposta 200 senza creare token.
     * Endpoint /password-reset/confirm: se deleted → 400 `invalid_token`; se locked → 400 `account_locked`.
     * Test da aggiungere: request locked/deleted (nessun token creato) e confirm locked/deleted (errori sopra, token unused).
     * Helper eventuali: `MarkLockedAsync` / `SoftDeleteAsync` in `UserRepository` se servirà; cleanup opzionale per token orfani di utenti deleted.
   - Test ancora da implementare (TODO):
     * Password policy fail: confirm con password debole → 400 password_policy_failed, password invariata.
     * Password uguale all’attuale: confirm con stessa password → 400 password_must_be_different.
     * Token formato invalido: confirm con token malformato o lunghezza errata → 400 invalid_token.
     * Race doppia conferma: due conferme concorrenti sullo stesso token → una 200, una 400; password cambiata una sola volta.
     * Cleanup/retention: forzare scadenze/usate oltre retention e verificare DeleteExpiredAsync.
     * Cascade delete: cancellazione utente elimina i reset associati.
     * Hash/token check: solo hash salvato (no plain), SHA256(token) == token_hash.
     * Token uniqueness stress (opzionale): 100 reset paralleli senza collisioni.
   - Input validation: email vuota/null → 400; token vuoto/malformed → 400 invalid_token; mismatch password → 400 invalid_input.
   - Race condition: due conferme simultanee sullo stesso token → una 200, una 400 invalid_token; password cambiata una sola volta.
   - Revoca sessioni/refresh: dopo reset, tutte le sessioni (`user_sessions`) e i refresh attivi devono risultare revocati; vecchi access/refresh non validi.
   - Audit logging strutturato: da valutare più avanti; al momento solo Serilog, i test su eventi possono essere messi da parte o coperti con logger finto.
   - Cascade delete: cancellazione utente elimina i reset associati (FK ON DELETE CASCADE).
   - Token uniqueness stress test (100 utenti simultanei): opzionale, non indispensabile per l'MVP.

5) Documentazione:
   - Aggiornare `appsettings.guida.md` con sezione PasswordReset e opzioni.
   - Aggiungere breve nota in README o appsettings.guida su uso dei token (in prod via email).

6) Cleanup:
   - Estendere `ExpiredCleanupService` per includere `PasswordResetRepository.DeleteExpiredAsync(nowIso, batchSize)`.
   - Aggiornare `CleanupOptions` se serve un batch separato o riusare quello esistente.

7) Verifica finale:
   - Eseguire `dotnet test tests/SecureAuthMinimalApi.Tests/SecureAuthMinimalApi.Tests.csproj`.
   - Rigenerare tag `tools\\update-tags.ps1`.

--------------------------------------------------------------------------
---- NOTE NON OBBLIGATORIE----
# Test Password Reset - Descrizione Dettagliata

## Setup e Utilities

### Test Base Class
```csharp
public class PasswordResetTests : IAsyncLifetime
{
    private WebApplicationFactory<Program> _factory;
    private HttpClient _client;
    private IServiceScope _scope;
    private IDbConnection _connection;
    
    public async Task InitializeAsync()
    {
        var config = new Dictionary<string, string>
        {
            ["PasswordReset:ExpirationMinutes"] = "30",
            ["PasswordReset:RequireConfirmed"] = "true",
            ["PasswordReset:IncludeTokenInResponseForTesting"] = "true",
            ["PasswordReset:RetentionDays"] = "7"
        };
        
        _factory = CreateFactory(config);
        _client = _factory.CreateClient();
        _scope = _factory.Services.CreateScope();
        _connection = _scope.ServiceProvider.GetRequiredService<IDbConnection>();
    }
    
    public async Task DisposeAsync()
    {
        _scope?.Dispose();
        _client?.Dispose();
        await _factory?.DisposeAsync();
    }
}
```

### Helper Methods
```csharp
// Crea utente test con email confermata
private async Task<(string userId, string email, string password)> CreateConfirmedUserAsync()
{
    var email = $"test-{Guid.NewGuid():N}@example.com";
    var password = "TestPassword123!";
    
    await _client.PostAsJsonAsync("/register", new 
    { 
        email, 
        password, 
        confirmPassword = password 
    });
    
    // Conferma email direttamente in DB
    await _connection.ExecuteAsync(
        "UPDATE users SET email_confirmed_at_utc = datetime('now') WHERE email_normalized = @email",
        new { email = email.ToLowerInvariant() });
    
    var userId = await _connection.QuerySingleAsync<string>(
        "SELECT id FROM users WHERE email_normalized = @email",
        new { email = email.ToLowerInvariant() });
    
    return (userId, email, password);
}

// Crea utente test con email NON confermata
private async Task<(string userId, string email, string password)> CreateUnconfirmedUserAsync()
{
    var email = $"test-{Guid.NewGuid():N}@example.com";
    var password = "TestPassword123!";
    
    await _client.PostAsJsonAsync("/register", new 
    { 
        email, 
        password, 
        confirmPassword = password 
    });
    
    var userId = await _connection.QuerySingleAsync<string>(
        "SELECT id FROM users WHERE email_normalized = @email",
        new { email = email.ToLowerInvariant() });
    
    return (userId, email, password);
}

// Request reset e estrae token da response
private async Task<string> RequestResetAndGetTokenAsync(string email)
{
    var response = await _client.PostAsJsonAsync("/password-reset/request", 
        new { email });
    
    response.EnsureSuccessStatusCode();
    var result = await response.Content.ReadFromJsonAsync<JsonElement>();
    
    return result.GetProperty("resetToken").GetString();
}

// Conferma reset con token
private async Task<HttpResponseMessage> ConfirmResetAsync(
    string token, 
    string newPassword, 
    string confirmPassword = null)
{
    confirmPassword ??= newPassword;
    
    return await _client.PostAsJsonAsync("/password-reset/confirm", new 
    { 
        token, 
        newPassword, 
        confirmPassword 
    });
}

// Tenta login
private async Task<HttpResponseMessage> LoginAsync(string email, string password)
{
    return await _client.PostAsJsonAsync("/login", new { email, password });
}

// Manipola DB per scadere token
private async Task ExpireTokenAsync(string token)
{
    var tokenHash = HashToken(token);
    await _connection.ExecuteAsync(
        "UPDATE password_resets SET expires_at_utc = datetime('now', '-1 hour') WHERE token_hash = @tokenHash",
        new { tokenHash });
}

// Manipola DB per marcare token come usato
private async Task MarkTokenUsedAsync(string token)
{
    var tokenHash = HashToken(token);
    await _connection.ExecuteAsync(
        "UPDATE password_resets SET used_at_utc = datetime('now') WHERE token_hash = @tokenHash",
        new { tokenHash });
}

// Calcola hash token (deve matchare implementazione prod)
private string HashToken(string token)
{
    using var sha256 = SHA256.Create();
    var bytes = Encoding.UTF8.GetBytes(token);
    var hash = sha256.ComputeHash(bytes);
    return Convert.ToHexString(hash).ToLowerInvariant();
}

// Conta reset attivi per user
private async Task<int> CountActiveResetsForUserAsync(string userId)
{
    return await _connection.ExecuteScalarAsync<int>(
        @"SELECT COUNT(*) FROM password_resets 
          WHERE user_id = @userId 
          AND used_at_utc IS NULL 
          AND expires_at_utc > datetime('now')",
        new { userId });
}

// Conta sessioni attive per user
private async Task<int> CountActiveSessionsAsync(string userId)
{
    return await _connection.ExecuteScalarAsync<int>(
        "SELECT COUNT(*) FROM sessions WHERE user_id = @userId AND revoked_at_utc IS NULL",
        new { userId });
}

// Conta refresh token attivi per user
private async Task<int> CountActiveRefreshTokensAsync(string userId)
{
    return await _connection.ExecuteScalarAsync<int>(
        "SELECT COUNT(*) FROM refresh_tokens WHERE user_id = @userId AND revoked_at_utc IS NULL",
        new { userId });
}
```

---

## Test 1: Flow Completo Successo

**Nome:** `RequestAndConfirm_WithValidData_UpdatesPasswordAndRevokesTokens`

**Descrizione:** Verifica il flusso completo end-to-end di reset password con successo.

**Steps:**
1. Crea utente test con email confermata e password "OldPassword123!"
2. Crea sessione attiva: login con vecchia password, salva access token
3. Crea refresh token attivo
4. Request reset password per email utente
5. Verifica response 200 con `ok: true` e `resetToken` presente
6. Verifica in DB: 1 reset creato per user, expires_at_utc nel futuro, used_at_utc null
7. Confirm reset con token e nuova password "NewPassword123!"
8. Verifica response 200 con `ok: true`
9. Verifica in DB: reset marcato come usato (used_at_utc non null)
10. Verifica in DB: password_hash utente cambiato
11. Tenta login con vecchia password "OldPassword123!" → 401
12. Login con nuova password "NewPassword123!" → 200, nuovo access token
13. Verifica in DB: sessione precedente revocata (revoked_at_utc non null)
14. Verifica in DB: refresh token precedente revocato (revoked_at_utc non null)
15. Verifica access token precedente non funziona più per chiamate autenticate

**Assertions:**
- Response `/request` status 200
- Response `/request` contiene `resetToken` stringa 43 caratteri
- DB: 1 record in `password_resets` per user
- DB: `token_hash` è stringa 64 caratteri hex (SHA256)
- DB: `expires_at_utc` > now
- DB: `used_at_utc` inizialmente null
- Response `/confirm` status 200
- DB: `used_at_utc` non null dopo confirm
- DB: `password_hash` diverso da hash originale
- Login vecchia password status 401
- Login nuova password status 200
- DB: sessione precedente con `revoked_at_utc` non null
- DB: refresh token precedente con `revoked_at_utc` non null
- Chiamata API con vecchio access token → 401

---

## Test 2: Token Scaduto

**Nome:** `ConfirmReset_WithExpiredToken_Returns400InvalidToken`

**Descrizione:** Verifica che token scaduto non possa essere usato e password non cambi.

**Steps:**
1. Crea utente con email confermata e password "OldPassword123!"
2. Request reset → ottieni token
3. Manipola DB: retrodata `expires_at_utc` a 1 ora fa
4. Confirm con token scaduto e nuova password "NewPassword123!"
5. Verifica response 400 con error "invalid_token"
6. Verifica in DB: password_hash NON cambiato (ancora uguale a hash originale)
7. Verifica in DB: reset NON marcato come usato (used_at_utc ancora null)
8. Login con password originale "OldPassword123!" → ancora 200 (funziona)

**Assertions:**
- Response `/confirm` status 400
- Response body: `{ ok: false, error: "invalid_token" }`
- DB: `password_hash` identico a prima
- DB: `used_at_utc` null
- Login con vecchia password status 200

---

## Test 3: Token Già Usato

**Nome:** `ConfirmReset_WithAlreadyUsedToken_Returns400InvalidToken`

**Descrizione:** Verifica che token non possa essere riutilizzato dopo primo uso.

**Steps:**
1. Crea utente con email confermata
2. Request reset → token
3. Confirm con token e password "FirstPassword123!" → 200
4. Verifica in DB: used_at_utc non null, password cambiata
5. Tenta secondo confirm con stesso token e password "SecondPassword456!"
6. Verifica response 400 "invalid_token"
7. Verifica in DB: password ancora "FirstPassword123!" (non "SecondPassword456!")
8. Login con "FirstPassword123!" → 200
9. Login con "SecondPassword456!" → 401

**Assertions:**
- Primo confirm status 200
- DB dopo primo confirm: `used_at_utc` non null
- Secondo confirm status 400
- Response body secondo confirm: `{ ok: false, error: "invalid_token" }`
- DB: password hash corrisponde a "FirstPassword123!"
- Login "FirstPassword123!" status 200
- Login "SecondPassword456!" status 401

---

## Test 4: Nuova Richiesta Invalida Precedente

**Nome:** `RequestReset_MultipleTimes_InvalidatesPreviousTokens`

**Descrizione:** Verifica che nuova richiesta reset invalidi automaticamente token precedenti non usati.

**Steps:**
1. Crea utente con email confermata
2. Request reset #1 → salva token1
3. Verifica in DB: 1 reset attivo per user, used_at_utc null
4. Attendi 1 secondo (per differenziare timestamp)
5. Request reset #2 → salva token2
6. Verifica in DB: 2 reset totali per user
7. Verifica in DB: reset #1 ha used_at_utc non null (invalidato)
8. Verifica in DB: reset #2 ha used_at_utc null (attivo)
9. Tenta confirm con token1 → 400 "invalid_token"
10. Confirm con token2 e nuova password → 200
11. Verifica password cambiata

**Assertions:**
- Dopo prima request: 1 reset attivo (`used_at_utc IS NULL`)
- Dopo seconda request: 1 reset attivo (solo il nuovo)
- Reset #1: `used_at_utc` non null dopo seconda request
- Reset #2: `used_at_utc` null dopo seconda request
- Confirm con token1 status 400
- Confirm con token2 status 200
- Password hash cambiato

**Note:** Questo test verifica la chiamata a `InvalidatePreviousForUserAsync` in `/request`.

---

## Test 5: Email Non Trovata

**Nome:** `RequestReset_WithNonexistentEmail_Returns200WithoutCreatingToken`

**Descrizione:** Verifica che richiesta con email inesistente non leak informazioni (sempre 200) e non crei token.

**Steps:**
1. Request reset con email "nonexistent@example.com" (non registrata)
2. Verifica response 200 con `ok: true`
3. Verifica response NON contiene `resetToken` (anche con flag test abilitato)
4. Verifica in DB: 0 reset creati
5. Verifica audit log: evento "password_reset_email_not_found" con email e IP

**Assertions:**
- Response status 200
- Response body: `{ ok: true }` (no resetToken)
- DB: `SELECT COUNT(*) FROM password_resets` per email normalizzata → 0
- Audit log contiene evento con type "email_not_found"

---

## Test 6: Email Non Confermata con RequireConfirmed=true

**Nome:** `RequestReset_WithUnconfirmedEmail_WhenRequireConfirmedTrue_Returns200WithoutToken`

**Descrizione:** Verifica che utente con email non confermata non possa richiedere reset quando config richiede conferma.

**Steps:**
1. Config test: `PasswordReset:RequireConfirmed = true`
2. Crea utente con email NON confermata (email_confirmed_at_utc null)
3. Request reset per email utente
4. Verifica response 200 con `ok: true`
5. Verifica response NON contiene `resetToken`
6. Verifica in DB: 0 reset creati per user
7. Verifica audit log: evento "password_reset_blocked_unconfirmed" con user_id

**Assertions:**
- Response status 200
- Response body: `{ ok: true }` (no leak)
- DB: `SELECT COUNT(*) FROM password_resets WHERE user_id = @userId` → 0
- Audit log: evento "blocked_unconfirmed" presente

---

## Test 7: Email Non Confermata con RequireConfirmed=false

**Nome:** `RequestReset_WithUnconfirmedEmail_WhenRequireConfirmedFalse_CreatesToken`

**Descrizione:** Verifica che con RequireConfirmed=false, anche email non confermate possano resettare password.

**Steps:**
1. Ricrea factory con config: `PasswordReset:RequireConfirmed = false`
2. Crea utente con email NON confermata
3. Request reset
4. Verifica response 200 con `resetToken` presente
5. Verifica in DB: 1 reset creato per user
6. Confirm con token e nuova password → 200
7. Login con nuova password → 200

**Assertions:**
- Response status 200
- Response body contiene `resetToken`
- DB: 1 reset con `user_id` corretto e `used_at_utc` null
- Confirm status 200
- DB: reset marcato come usato
- Login con nuova password status 200

---

## Test 8: Account Locked in Request

**Nome:** `RequestReset_WithLockedAccount_Returns200WithoutToken`

**Descrizione:** Verifica che account bloccato non possa richiedere reset (no leak, nessun token).

**Steps:**
1. Crea utente con email confermata
2. Manipola DB: `UPDATE users SET is_locked = 1 WHERE id = @userId`
3. Request reset per email utente
4. Verifica response 200 con `ok: true`
5. Verifica response NON contiene `resetToken`
6. Verifica in DB: 0 reset creati
7. Verifica audit log: evento "password_reset_blocked_locked" con user_id

**Assertions:**
- Response status 200
- Response body: `{ ok: true }`
- DB: 0 reset per user
- Audit log: evento "blocked_locked"

---

## Test 9: Account Locked in Confirm

**Nome:** `ConfirmReset_WithLockedAccount_Returns400AccountLocked`

**Descrizione:** Verifica che se account viene bloccato dopo request ma prima di confirm, conferma fallisce.

**Steps:**
1. Crea utente con email confermata, account attivo
2. Request reset → token
3. Verifica in DB: reset creato
4. Manipola DB: `UPDATE users SET is_locked = 1 WHERE id = @userId`
5. Confirm con token e nuova password
6. Verifica response 400 con error "account_locked"
7. Verifica in DB: password NON cambiata
8. Verifica in DB: reset NON marcato come usato (used_at_utc null)

**Assertions:**
- Response status 400
- Response body: `{ ok: false, error: "account_locked" }`
- DB: password hash identico a prima
- DB: `used_at_utc` null

**Note:** Qui possiamo essere specifici con "account_locked" perché utente ha dimostrato possesso token valido.

---

## Test 10: Account Deleted

**Nome:** `ConfirmReset_WithDeletedAccount_Returns400InvalidToken`

**Descrizione:** Verifica che account cancellato non possa completare reset.

**Steps:**
1. Crea utente con email confermata
2. Request reset → token
3. Manipola DB: `UPDATE users SET deleted_at_utc = datetime('now') WHERE id = @userId`
4. Confirm con token
5. Verifica response 400 con error "invalid_token" (non leak che account deleted)
6. Verifica in DB: reset non marcato come usato

**Assertions:**
- Response status 400
- Response body: `{ ok: false, error: "invalid_token" }`
- DB: `used_at_utc` null

---

## Test 11: Password Policy Fail

**Nome:** `ConfirmReset_WithWeakPassword_Returns400PasswordPolicyFailed`

**Descrizione:** Verifica validazione password contro policy configurata.

**Steps:**
1. Crea utente con email confermata
2. Request reset → token
3. Confirm con password debole "123" (sotto requisiti policy)
4. Verifica response 400 con error "password_policy_failed"
5. Verifica response contiene dettagli errori validazione (es. "minLength", "requireDigit", etc.)
6. Verifica in DB: password NON cambiata
7. Verifica in DB: reset NON marcato come usato
8. Login con password originale → ancora funziona

**Assertions:**
- Response status 400
- Response body: `{ ok: false, error: "password_policy_failed", details: [...] }`
- Details array non vuoto con errori specifici
- DB: password hash invariato
- DB: `used_at_utc` null
- Login con vecchia password status 200

**Varianti da testare:**
- Password troppo corta (es. "Ab1!")
- Password senza digit (es. "Abcdefgh!")
- Password senza uppercase (es. "abcdefgh1!")
- Password senza lowercase (es. "ABCDEFGH1!")
- Password senza special char se richiesto (es. "Abcdefgh1")

---

## Test 12: Password Uguale a Quella Attuale

**Nome:** `ConfirmReset_WithSamePassword_Returns400PasswordMustBeDifferent`

**Descrizione:** Verifica che non si possa resettare alla stessa password corrente.

**Steps:**
1. Crea utente con password "CurrentPassword123!"
2. Request reset → token
3. Confirm con stessa password "CurrentPassword123!"
4. Verifica response 400 con error "password_must_be_different"
5. Verifica in DB: reset NON marcato come usato
6. Login con password corrente → ancora funziona

**Assertions:**
- Response status 400
- Response body: `{ ok: false, error: "password_must_be_different" }`
- DB: `used_at_utc` null
- Login status 200

**Implementazione check:** Confronta hash nuova password (con stesso salt) contro `user.password_hash`.

---

## Test 13: Race Condition Doppia Conferma

**Nome:** `ConfirmReset_SimultaneousRequests_OnlyOneSucceeds`

**Descrizione:** Verifica atomicità: due conferme simultanee con stesso token, solo una riesce.

**Steps:**
1. Crea utente con email confermata e password "OldPassword123!"
2. Request reset → token
3. Prepara due task confirm identiche con stesso token e password "NewPassword123!"
4. Esegui con `Task.WhenAll(task1, task2)`
5. Verifica: esattamente una task ha response 200, altra ha 400
6. Verifica in DB: password cambiata a "NewPassword123!" (una sola volta)
7. Verifica in DB: reset marcato come usato con un solo timestamp
8. Login con "NewPassword123!" → 200
9. Login con "OldPassword123!" → 401

**Assertions:**
- Risultati tasks: uno status 200, uno status 400
- Response 200: `{ ok: true }`
- Response 400: `{ ok: false, error: "invalid_token" }`
- DB: `used_at_utc` non null con singolo valore
- DB: password hash corrisponde a "NewPassword123!"
- Login "NewPassword123!" status 200
- Login "OldPassword123!" status 401

**Implementazione critica:** `MarkUsedAsync` deve fare UPDATE con WHERE che include `used_at_utc IS NULL` e ritornare affected rows. Se 0, significa altro thread ha già usato token.

---

## Test 14: Input Validation

**Nome (multipli):** 
- `RequestReset_WithEmptyEmail_Returns400InvalidInput`
- `ConfirmReset_WithEmptyToken_Returns400InvalidInput`
- `ConfirmReset_WithEmptyPassword_Returns400InvalidInput`
- `ConfirmReset_WithMismatchedPasswords_Returns400InvalidInput`

**Descrizione:** Verifica validazione input su entrambi endpoint.

### 14a: Email vuota in request
**Steps:**
1. POST `/password-reset/request` con `{ "email": "" }`
2. Verifica response 400 con error "invalid_input"

**Assertions:**
- Response status 400
- Response body: `{ ok: false, error: "invalid_input" }`

### 14b: Email null in request
**Steps:**
1. POST `/password-reset/request` con `{ "email": null }`
2. Verifica response 400

### 14c: Token vuoto in confirm
**Steps:**
1. POST `/password-reset/confirm` con `{ "token": "", "newPassword": "Test123!", "confirmPassword": "Test123!" }`
2. Verifica response 400

### 14d: Password vuota in confirm
**Steps:**
1. Request reset valido → token
2. Confirm con `{ "token": token, "newPassword": "", "confirmPassword": "" }`
3. Verifica response 400

### 14e: Password mismatch in confirm
**Steps:**
1. Request reset → token
2. Confirm con `{ "token": token, "newPassword": "Password1!", "confirmPassword": "Password2!" }`
3. Verifica response 400 con error "invalid_input"

---

## Test 15: Token Format Invalido

**Nome:** `ConfirmReset_WithMalformedToken_Returns400InvalidToken`

**Descrizione:** Verifica che token con formato invalido venga rifiutato.

**Steps:**
1. Crea utente con email confermata
2. Tenta confirm con token malformato (es. "not-a-valid-base64url-token!@#$")
3. Verifica response 400 con error "invalid_token"
4. Tenta confirm con token lunghezza sbagliata (es. "abc123" - troppo corto)
5. Verifica response 400

**Assertions:**
- Response status 400 per token malformato
- Response status 400 per token corto
- Response body: `{ ok: false, error: "invalid_token" }`

**Varianti:**
- Token con caratteri non Base64Url (es. spazi, +, /)
- Token troppo corto (< 43 caratteri)
- Token troppo lungo (> 43 caratteri)
- Token null

---

## Test 16: Token Hash Corretto

**Nome:** `RequestReset_StoresHashNotPlainText`

**Descrizione:** Verifica che solo hash token sia salvato, mai plain-text.

**Steps:**
1. Crea utente con email confermata
2. Request reset → ottieni token da response
3. Query DB: `SELECT token_hash FROM password_resets WHERE user_id = @userId`
4. Verifica token_hash è stringa 64 caratteri hex (SHA256)
5. Verifica token_hash != token (non plain-text)
6. Ricalcola SHA256 del token ricevuto
7. Verifica hash calcolato == token_hash in DB
8. Confirm con token originale → 200 (hash matching funziona)

**Assertions:**
- DB: `token_hash` è string di 64 caratteri [0-9a-f]
- DB: `token_hash` != token originale
- SHA256(token) == token_hash da DB
- Confirm con token funziona (verifica hash comparison)

---

## Test 17: Token Expiration Configurabile

**Nome:** `RequestReset_WithCustomExpiration_ExpiresAtConfiguredTime`

**Descrizione:** Verifica che expiration time segue config.

**Steps:**
1. Ricrea factory con config `PasswordReset:ExpirationMinutes = 15`
2. Crea utente
3. Request reset al tempo T0
4. Query DB: `SELECT expires_at_utc FROM password_resets WHERE user_id = @userId`
5. Verifica expires_at_utc ~= T0 + 15 minuti (tolleranza ±5 secondi)
6. Attendi o manipola tempo per superare 15 minuti
7. Confirm → 400 token expired

**Assertions:**
- DB: `expires_at_utc` è circa now + 15 minuti
- Dopo 15 minuti: confirm status 400

---

## Test 18: Cleanup Token Scaduti

**Nome:** `CleanupService_DeletesExpiredAndUsedTokens`

**Descrizione:** Verifica cleanup automatico token scaduti/usati.

**Steps:**
1. Crea utente
2. Request reset #1 → token1
3. Manipola DB: retrodata expires_at_utc a 10 giorni fa (oltre retention)
4. Request reset #2 → token2, confirm e usa
5. Manipola DB: retrodata used_at_utc di token2 a 10 giorni fa
6. Request reset #3 → token3 (attivo, non scaduto)
7. Esegui cleanup con `PasswordResetRepository.DeleteExpiredAndUsedAsync(nowMinus7Days, 1000)`
8. Verifica in DB: token1 e token2 eliminati (scaduto/usato oltre retention)
9. Verifica in DB: token3 ancora presente (attivo recente)

**Assertions:**
- Prima cleanup: 3 reset in DB
- Dopo cleanup: 1 reset in DB (solo token3)
- Token3 è quello con `expires_at_utc` recente e `used_at_utc` null

**Query cleanup:**
```sql
DELETE FROM password_resets 
WHERE id IN (
    SELECT id FROM password_resets 
    WHERE expires_at_utc < @expiresBeforeIso 
       OR (used_at_utc IS NOT NULL AND used_at_utc < @expiresBeforeIso)
    LIMIT @batchSize
)
```

---

## Test 19: Revoca Sessioni e Refresh Token

**Nome:** `ConfirmReset_RevokesAllUserSessionsAndRefreshTokens`

**Descrizione:** Verifica che dopo reset tutti token/sessioni attivi siano revocati.

**Steps:**
1. Crea utente con email confermata
2. Login → salva accessToken1 e refreshToken1
3. Crea seconda sessione con altro dispositivo → accessToken2 e refreshToken2
4. Verifica in DB: 2 sessioni attive, 2 refresh token attivi per user
5. Request e confirm reset password
6. Verifica in DB: entrambe sessioni con `revoked_at_utc` non null
7. Verifica in DB: entrambi refresh token con `revoked_at_utc` non null
8. Tenta refresh con refreshToken1 → 401
9. Tenta refresh con refreshToken2 → 401
10. Tenta chiamata API autenticata con accessToken1 → 401 (se validato contro session revocata)
11. Tenta chiamata API con accessToken2 → 401

**Assertions:**
- Prima reset: 2 sessioni con `revoked_at_utc IS NULL`
- Prima reset: 2 refresh token con `revoked_at_utc IS NULL`
- Dopo reset: 2 sessioni con `revoked_at_utc IS NOT NULL`
- Dopo reset: 2 refresh token con `revoked_at_utc IS NOT NULL`
- Refresh con vecchi token status 401
- API calls con vecchi access token status 401

---

## Test 20: Audit Logging Completo

**Nome:** `PasswordResetFlow_LogsAllSecurityEvents`

**Descrizione:** Verifica che tutti eventi sicurezza siano loggati correttamente.

**Steps:**
1. Mock o setup audit log capture
2. Request con email non trovata → verifica log "email_not_found"
3. Request con email non confermata (RequireConfirmed=true) → log "blocked_unconfirmed"
4. Request con account locked → log "blocked_locked"
5. Request con account valido → log "password_reset_requested" con user_id
6. Confirm con token scaduto → log "password_reset_failed" con reason "expired"
7. Confirm con password debole → log "password_reset_failed" con reason "policy_failed"
8. Confirm successo → log "password_reset_completed" con user_id e contatori revoke

**Assertions per ogni evento:**
- Log entry presente con timestamp
- Log contiene tipo evento corretto
- Log contiene user_id quando applicabile
- Log contiene client_ip (se tracciato)
- Log contiene metadata rilevante (es. reason per fail)

**Setup:** Usare `ILogger` mock o in-memory logger per catturare log entries durante test.

---

## Test 21: Foreign Key Cascade Delete

**Nome:** `UserDelete_CascadeDeletesPasswordResets`

**Descrizione:** Verifica che cancellazione utente elimini anche reset token.

**Steps:**
1. Crea utente
2. Request reset → token creato
3. Verifica in DB: 1 reset per user
4. Elimina utente: `DELETE FROM users WHERE id = @userId` (o soft delete se implementato)
5. Verifica in DB: 0 reset per user (cascade delete funziona)

**Assertions:**
- Prima delete: 1 reset in `password_resets`
- Dopo delete user: 0 reset con `user_id` corrispondente

**Schema requirement:** `FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE`

---

## Test 22: Token Uniqueness

**Nome:** `MultipleRequests
_GenerateUniqueTokens`

**Descrizione:** Verifica che ogni richiesta generi token univoco.

**Steps:**
1. Crea 100 utenti
2. Request reset per tutti simultaneamente con `Task.WhenAll`
3. Raccoglie tutti token generati
4. Verifica tutti token sono distinti (no duplicati)
5. Verifica in DB: tutti token_hash sono univoci (unique constraint)

**Assertions:**
- 100 token generati
- 100 token distinti (HashSet.Count == 100)
- DB: 100 record in `password_resets` con `token_hash` univoci

---

## Test 23: Response Non Leak Info in Errori

**Nome:** `PasswordResetEndpoints_DoNotLeakAccountInformation`

**Descrizione:** Verifica che response non leak esistenza account o stato.

**Steps:**
1. Request con email non esistente → 200
2. Request con email non confermata (RequireConfirmed=true) → 200
3. Request con account locked → 200
4. Request con account deleted → 200
5. Verifica tutte response identiche: `{ ok: true }` senza dettagli

**Assertions:**
- Tutte request status 200
- Tutte response body identiche
- Nessuna response contiene `resetToken` per account invalidi
- Nessun header differenziante (timing potrebbe variare ma non controllabile)

---

## Riepilogo Test Coverage

**Totale test:** 23

**Categorie:**
- **Flow successo:** 1 test (end-to-end completo)
- **Token validity:** 3 test (scaduto, usato, invalidato)
- **Account states:** 4 test (non trovato, non confermato, locked, deleted)
- **Password validation:** 2 test (policy, same password)
- **Concurrency:** 1 test (race condition)
- **Input validation:** 5 test (email vuota, token vuoto, password mismatch, malformed token)
- **Security:** 4 test (hash storage, no leak, audit log, token uniqueness)
- **Infrastructure:** 3 test (cleanup, revoke tokens, cascade delete)

**Code coverage atteso:**
- Repository methods: 100%
- Endpoint handlers: 100%
- Validation logic: 100%
- Transaction rollback paths: ✓
- Error handling: ✓

**Test runtime stimato:** ~30-60 secondi per suite completa (con DB in-memory e parallelizzazione xUnit). 
---------------------------------------------

