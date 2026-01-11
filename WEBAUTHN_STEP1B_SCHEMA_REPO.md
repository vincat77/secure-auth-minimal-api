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
- Storage challenge: decidere tabella o cache in-memory per opzioni register/auth legate a `sessionId` con TTL ≤ 5 min (campo `expires_at_utc`).

### Sicurezza
- Memorizzare solo public key/signCount/aaguid/userId/credentialId.
- Nessun segreto condiviso, nessuna attestation/raw salvata.

### Output
- Schema e repository pronti; nessun endpoint ancora attivo.
