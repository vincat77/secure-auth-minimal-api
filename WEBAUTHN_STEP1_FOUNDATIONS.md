## Step 1 – Fondamenta FIDO2/WebAuthn

### Scopo
Preparare opzioni, servizio FIDO2 e schema/repository per credenziali senza toccare il flusso esistente.

### Attività
- Aggiungere `FidoOptions` (RpId, Origin, RpName, ChallengeTtlMinutes=5) e binding in `Program.cs`.
- Creare `Services/Fido2Service.cs` che incapsula `Fido2-Net-Lib` (config rpId/origin, generate challenge, validate attestation/assertion).
- Aggiungere modello `FidoCredential` e tabella `fido_credentials` (credentialId, publicKey, signCount, aaguid, userId, created_at_utc) + indici su `credential_id` e `user_id`.
- Repository `FidoCredentialRepository` (Create/UpdateSignCount/GetByCredentialId/GetByUserId).
- Storage challenge: tabella o cache in-memory per opzioni registrazione/autenticazione legata a sessionId con TTL ≤ 5 minuti.

### Sicurezza da rispettare
- Non loggare challenge, credentialId, attestation/raw.
- Challenge legata a sessione e scade in 5 minuti.
- Salva solo public key, signCount, aaguid, userId, credentialId.

### Test minimi
- Binding opzioni valido (rpId/origin presenti).
- Repo CRUD credenziali (signCount update).
- Challenge scade dopo TTL.

### Output
- Opzioni registrate, servizio FIDO2 pronto, schema/Repo creati, nessun endpoint ancora esposto.
