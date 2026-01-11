## Step 2 – Endpoint WebAuthn

### Scopo
Esporre gli endpoint WebAuthn senza cambiare il flusso TOTP esistente.

### Endpoint da aggiungere
- `POST /webauthn/register/options`: genera opzioni di registrazione, challenge legata a sessione, TTL 5 min.
- `POST /webauthn/register/verify`: valida attestation, salva credenziale (publicKey, credentialId, signCount, aaguid), nessun log sensibile.
- `POST /webauthn/authenticate/options`: genera opzioni di autenticazione per le credenziali dell’utente.
- `POST /webauthn/authenticate/verify`: valida assertion, aggiorna signCount, marca sessione MFA-satisfied, imposta claim `amr=["pwd","fido2"]` e `auth_time`.

### Requisiti sicurezza (endpoint)
- Verificare origin e rpId in `verify`.
- Sign counter obbligatorio (rifiutare decrementi).
- Challenge mai loggata e scade dopo TTL.
- Nessuna attestation/raw nei log.

### Integrazione sessione/JWT
- Dopo `authenticate/verify`: `session.MfaSatisfied = true`, `auth_time` aggiornato, claim `amr` include `fido2`.
- TOTP resta valido come fallback: non modificare endpoint TOTP.

### Test minimi
- Flow registrazione: options → verify → credenziale salvata.
- Flow autenticazione: options → verify → sessione marcata MFA, amr/auth_time presenti.
- SignCount incrementale (failure se minore).
- TTL challenge: scaduto → 400/410.
