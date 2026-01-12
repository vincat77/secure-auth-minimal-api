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
- Positivi:
  - `WebAuthnRegister_Flow_SavesCredential`: options → verify con attestation valida → credenziale salvata in repo (credentialId/publicKey/aaguid/signCount/userId).
- Negativi:
  - `WebAuthnRegister_InvalidOrigin_Returns400`: attestation con origin errata → 400/403.
  - `WebAuthnRegister_InvalidRpId_Returns400`: rpId errata → 400/403.
  - `WebAuthnRegister_ExpiredChallenge_Returns410`: challenge scaduta (>TTL) → 410/400.
  - `WebAuthnRegister_LogsAreSanitized`: logger fake senza challenge/credentialId/raw (Assert.DoesNotContain).

### Note operative
- Endpoint protetti da sessione autenticata; nessun requisito MFA per la registrazione della chiave.
- Usa storage challenge di Step 1B (tabella `fido_challenges`).
- Mappare con `app.MapGroup("/webauthn")`.
 - Considerare `excludeCredentials` nelle options per evitare duplicati (passare le credenziali già registrate).
 - Attestazione: scegliere policy (packed/self) e accettare solo AAGUID attesi se si vuole ridurre superficie; altrimenti permettere self/none e documentare.
- Struttura codice: classe statica `WebAuthnRegisterEndpoints` con metodo `MapWebAuthnRegister(this WebApplication app)`, agganciato a `app.MapGroup("/webauthn")`.
