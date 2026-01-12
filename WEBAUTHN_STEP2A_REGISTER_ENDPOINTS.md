## Step 2A – Endpoint WebAuthn Registrazione (options/verify)

### Scopo
Esporre gli endpoint di registrazione WebAuthn senza modificare il flusso TOTP esistente.

### Endpoint
- `POST /webauthn/register/options`
  - Genera challenge (TTL 5 min), lega a `sessionId`, restituisce `PublicKeyCredentialCreationOptions`.
  - Carica o riceve userId/username/displayName dalla sessione corrente.
- `POST /webauthn/register/verify`
  - Valida attestation (origin/rpId), rifiuta dati mancanti/scaduti.
  - Salva credenziale in repo (`credentialId`, `publicKey`, `signCount`, `aaguid`, `userId`).
  - Nessun log di challenge/credentialId/raw attestation.

### Sicurezza
- Verificare `origin` e `rpId` nella attestation.
- Challenge legata a sessione e scade dopo TTL.
- Non salvare attestation/raw, solo chiave pubblica e metadata.
- Non loggare challenge/credentialId/raw attestation.

### Integrazione sessione/JWT
- Non cambia la sessione MFA (solo registra il metodo).
- TOTP resta attivo come fallback.

### Test (xUnit) da implementare
- Flow registrazione: options → verify con attestation valida → credenziale salvata in repo.
- Attestation con origin/rpId errati → 400/403.
- Challenge scaduta (>TTL) → 400/410.
- Log sanitizzati: logger fake senza challenge/credentialId/raw.

### Note operative
- Endpoint protetti da sessione autenticata; nessun requisito MFA per la registrazione della chiave.
- Usa storage challenge di Step 1B (tabella `fido_challenges`).
- Mappare con `app.MapGroup("/webauthn")`.
