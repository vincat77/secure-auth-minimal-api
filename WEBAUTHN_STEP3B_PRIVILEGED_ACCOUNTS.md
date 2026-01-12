## Step 3B – Account Privilegiati

### Scopo
Imporre FIDO2/WebAuthn obbligatorio per account privilegiati (admin/operator/support) al login e nelle policy.

### Attività
- Aggiungere configurazione/ruolo per utenti privilegiati (se non esiste).
- Obbligo: login deve richiedere FIDO2 per questi utenti (no bypass TOTP-only).
- Endpoint admin (se presenti): richiedere `RequireMfa`/`RequireRecentMfa` soddisfatta via FIDO2.
- Documentare la regola: privilegiato → deve avere e usare credenziale FIDO2.

### Sicurezza
- Nessun downgrade da FIDO2 a TOTP per privilegiati.
- Evitare di considerare “MFA satisfied” se solo TOTP presente per account privilegiato.

### Test (xUnit) da implementare
- Utente privilegiato: login senza WebAuthn → rifiutato; con WebAuthn → ok.
- Endpoint admin (se presenti): rifiutati senza `MfaSatisfied` da FIDO2.
