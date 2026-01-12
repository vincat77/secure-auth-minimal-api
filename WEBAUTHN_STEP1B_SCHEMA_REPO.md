## Step 1B – Schema e Repository Credenziali FIDO2

### Obiettivo
Creare storage per credenziali FIDO2 senza esporre endpoint.

### Azioni
- Aggiungere in `Data/DbInitializer.cs` la tabella `fido_credentials` con campi:
  - `credential_id` (PK/unique)
  - `public_key`
  - `sign_count`
  - `aaguid`
  - `user_id`
  - `created_at_utc`
  - Indici su `credential_id` (unique) e `user_id`.
- Creare `Models/FidoCredential.cs` con i campi sopra.
- Creare `Data/FidoCredentialRepository.cs` con metodi:
  - `CreateAsync`
  - `GetByCredentialIdAsync`
  - `GetByUserIdAsync`
  - `UpdateSignCountAsync`
- Storage challenge: usare tabella dedicata (es. `fido_challenges`) per opzioni register/auth legate a `sessionId` con TTL ≤ 5 min:
  - campi minimi `session_id`, `challenge`, `expires_at_utc`, `type` (register/auth), indice su `session_id` e `expires_at_utc`.
  - Pulizia: includere delete per challenge scadute in `ExpiredCleanupService`, coerente con purge per session/refresh/MFA.
- Formati consigliati:
  - `credential_id`: Base64Url (o blob) coerente con WebAuthn; salvare come TEXT se base64url.
  - `public_key`: stringa base64url della chiave CBOR (così come restituita da Fido2-Net-Lib).
  - `aaguid`: stringa GUID.
  - `sign_count`: intero non negativo.

### Sicurezza
- Memorizzare solo public key/signCount/aaguid/userId/credentialId.
- Nessun segreto condiviso, nessuna attestation/raw salvata.
- Validare `sign_count` in crescita: rifiutare decrementi in `UpdateSignCountAsync`.

### Output
- Schema e repository pronti; nessun endpoint ancora attivo.

### Test (xUnit) da implementare
- `FidoCredentialRepository_create_and_get`: inserisce credenziale e la recupera per credentialId/userId → valori attesi.
- `FidoCredentialRepository_update_signcount_monotonic`: update signCount maggiore → ok; minore → rifiutato/errore.
- Challenge storage (se tabella): insert con TTL, scadenza oltre TTL non deve essere recuperata.
- DbInitializer: crea tabella/indici `fido_credentials` senza errori (idempotente).

### Note operative (cleanup) con codice attuale
- Il servizio `ExpiredCleanupService` oggi esegue purge per sessioni (`SessionRepository.DeleteExpiredAsync`), refresh token (`RefreshTokenRepository.DeleteExpiredAsync`), MFA challenges (`MfaChallengeRepository.DeleteExpiredAsync`), password reset (`PasswordResetRepository.DeleteExpiredAsync`).
- Aggiungere un metodo simile in `FidoChallengeRepository` (nuovo) e chiamarlo da `ExpiredCleanupService` per eliminare le challenge FIDO scadute (chiave `expires_at_utc`, indice dedicato).
- Idempotenza: seguire lo schema attuale di `DbInitializer` (check e `EnsureColumn`) per creare tabella/indici senza rompere ambienti già esistenti.
