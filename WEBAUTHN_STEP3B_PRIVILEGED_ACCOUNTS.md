## Step 3B – Account Privilegiati

### Scopo
Imporre FIDO2/WebAuthn obbligatorio per account privilegiati (admin/operator/support) al login e nelle policy.

### Attività
- Aggiungere configurazione/ruolo per utenti privilegiati (se non esiste).
- Obbligo: login deve richiedere FIDO2 per questi utenti (no bypass TOTP-only).
- Endpoint admin (se presenti): richiedere `RequireMfa`/`RequireRecentMfa` soddisfatta via FIDO2.
- Documentare la regola: privilegiato → deve avere e usare credenziale FIDO2.
- Se non esistono endpoint admin nel codice attuale, pianificare come identificarli (es. gruppo dedicato o claim ruolo).

### Sicurezza
- Nessun downgrade da FIDO2 a TOTP per privilegiati.
- Evitare di considerare “MFA satisfied” se solo TOTP presente per account privilegiato.

### Test (xUnit) da implementare
- `Privileged_LoginWithoutWebAuthn_Forbidden`: utente admin senza credenziale FIDO2 → login rifiutato (401/403/429 a seconda della policy).
- `Privileged_LoginWithWebAuthn_Allows`: utente admin con FIDO2 → login ok, amr include fido2.
- `AdminEndpoint_RequiresFidoMfa`: chiamata a endpoint admin senza `MfaSatisfied` (FIDO2) → 401/403; con `MfaSatisfied` → 200.

### Note operative
- Aggiungere binding config (es. sezione `Privileged` con elenco username/ruoli o flag).
- Applicare la verifica in login: se utente è privilegiato e `MfaSatisfied` non include FIDO2 → bloccare o richiedere WebAuthn.
- Policy sugli endpoint admin: usare `RequireAuthorization("RequireMfa")` e verificare che `amr` includa `fido2`.
