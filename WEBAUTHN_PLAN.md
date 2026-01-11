## Piano d'azione – Integrazione FIDO2/WebAuthn (promemoria)

### Stato attuale
- MFA solo TOTP (challenge in `mfa_challenges`, sessione `UserSession` con flag MFA).
- Nessun codice WebAuthn/FIDO2 presente (nessun repo/modello/endpoint dedicato).
- Policy MFA esistenti: `RequireMfa`/`RequireRecentMfa` da integrare con esito FIDO2.

### Obiettivo
Aggiungere FIDO2/WebAuthn come secondo fattore (e opzionalmente passwordless) senza rompere i flussi TOTP esistenti, allineandosi ai requisiti indicati.

### Architettura prevista
- **Servizio**: `Services/Fido2Service.cs` che incapsula `Fido2-Net-Lib` per generation/verification di challenge.
- **Repository**: `Data/FidoCredentialRepository.cs` per persistere `credentialId`, `publicKey`, `signCount`, `aaguid`, `userId`.
- **Modello**: `Models/FidoCredential` con i campi sopra.
- **Config (IOptions)**: `FidoOptions` (`RpId`, `Origin`, `RpName`, TTL challenge ≤ 5 minuti).

### Endpoint da aggiungere (minimal API)
Mappare con `MapGroup("/webauthn")`:
- `POST /webauthn/register/options`
- `POST /webauthn/register/verify`
- `POST /webauthn/authenticate/options`
- `POST /webauthn/authenticate/verify`

### Requisiti di sicurezza (da implementare)
- Challenge generata server-side, legata a `sessionId`, TTL ≤ 5 minuti; mai loggare challenge/credentialId/raw attestation.
- Memorizzare solo: `credentialId`, `publicKey`, `signCount`, `aaguid`, `userId`.
- Verifiche WebAuthn: `origin`, `rpId`, sign counter anti-clone.
- Dopo `/authenticate/verify`: marcare sessione `mfa_satisfied=true`, aggiornare `auth_time`, emettere JWT con `amr=["pwd","fido2"]` e `auth_time`.
- FIDO2 obbligatorio per account privilegiati; valido come MFA step-up (non richiede recent-MFA).
- Nessun downgrade automatico da FIDO2 a TOTP; TOTP resta fallback separato.

### Passi operativi (ordine suggerito)
1) **Opzioni e servizi**: creare `FidoOptions`, registrare `Fido2Service` con `Fido2-Net-Lib` (rpId/origin/rpName).
2) **Schema/Repository**: aggiungere tabella `fido_credentials` con campi richiesti + index `user_id` e `credential_id`; implementare `FidoCredentialRepository`.
3) **Endpoint options**: `register/authenticate options` generano challenge legata a sessione (cache/DB) con TTL 5 min.
4) **Endpoint verify**: validazione attestation/assertion, update `signCount`, store credenziali, set `mfa_satisfied`, update `auth_time`, claim `amr`.
5) **Policy MFA**: integrare `RequireMfa`/`RequireRecentMfa` per accettare WebAuthn come soddisfazione MFA; obbligo per account privilegiati.
6) **Test**: unit/integration per flow register/authenticate, sign counter increment, TTL challenge, claim `amr`, nessun log di dati sensibili.

### Note e verifiche con il codice attuale
- Sessione/JWT: esiste emissione claim `amr`/`auth_time` solo per TOTP; servirà estenderla a WebAuthn.
- Logging: numerosi logger informativi; verificare di non loggare challenge/credential nei nuovi endpoint.
- Middleware/filtri: assicurarsi che `RequireMfa` consideri anche esiti FIDO2.
- Config: aggiungere sezione `Fido` in `appsettings.guida.md` e binding in `Program.cs`.

### Esclusioni esplicite
- Niente fingerprinting o passkey recovery via email.
- Nessun downgrade automatico da FIDO2 a TOTP.
- Nessun JS inline non necessario (solo chiamate API).
