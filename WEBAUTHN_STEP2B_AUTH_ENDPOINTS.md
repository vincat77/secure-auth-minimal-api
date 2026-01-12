## Step 2B – Endpoint WebAuthn Autenticazione (options/verify)

### Scopo
Esporre gli endpoint di autenticazione WebAuthn senza alterare TOTP.

### Endpoint
- `POST /webauthn/authenticate/options`
  - Genera challenge (TTL 5 min) per le credenziali dell’utente corrente.
  - Challenge legata a `sessionId`, restituisce `PublicKeyCredentialRequestOptions`.
- `POST /webauthn/authenticate/verify`
  - Valida assertion (origin/rpId).
  - Controlla `signCount` (rifiuta decrementi) e aggiorna il valore.
  - Marca la sessione `MfaSatisfied=true`, aggiorna `AuthTimeUtc`, imposta claim `amr` includendo `fido2`.
  - Nessun log di challenge/credentialId/raw assertion.

### Sicurezza
- Verificare `origin` e `rpId` nelle assertion.
- Challenge scade dopo TTL e non è loggata.
- Sign counter anti-clone obbligatorio (decrement → rifiuto).
- Non salvare raw assertion.

### Integrazione sessione/JWT
- Dopo verify: `session.MfaSatisfied=true`, `auth_time` aggiornato; JWT/IdToken con `amr=["pwd","fido2"]` e `auth_time`.
- Compatibile con policy `RequireMfa`/`RequireRecentMfa`.

### Test (xUnit) da implementare
- Flow auth: options → verify con assertion valida → sessione marcata MFA, claim amr/auth_time presenti.
- SignCount inferiore → rifiutato.
- Challenge scaduta → 400/410.
- Log sanitizzati: logger fake senza challenge/credentialId/raw.

### Note operative
- Endpoint protetti da sessione autenticata; options non richiede MFA, verify la soddisfa.
- Usa storage challenge di Step 1B (tabella `fido_challenges`).
- Mappare con `app.MapGroup("/webauthn")`.
