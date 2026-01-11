## Step 3 – Policy MFA e privilegi

### Scopo
Integrare WebAuthn nelle policy MFA esistenti e imporre obblighi per account privilegiati.

### Attività
- Estendere `RequireMfa`/`RequireRecentMfa` per accettare esito WebAuthn (flag sessione mfa_satisfied via FIDO2).
- Aggiungere configurazione per account privilegiati: se ruolo admin/operator → richiedere FIDO2 al login (no bypass TOTP-only).
- Aggiornare claim `amr`/`auth_time` in emissione token/sessioni per riflettere FIDO2.
- Mappare policy sugli endpoint sensibili già definiti (cambio password/email, revoke sessioni, disable/reset MFA, ecc.).

### Sicurezza
- Nessun downgrade automatico da FIDO2 a TOTP per account privilegiati.
- MFA “step-up” può essere soddisfatta da FIDO2 senza requisito di “recent” aggiuntivo se si ritiene sufficiente (documentare scelta).

### Test minimi
- Account privilegiato: login senza FIDO2 → rifiutato; con FIDO2 → ok.
- Endpoint step-up: sessione con FIDO2 accettata, senza → 401/403.
- Claim `amr` corretto per FIDO2; `auth_time` aggiornato al verify.
