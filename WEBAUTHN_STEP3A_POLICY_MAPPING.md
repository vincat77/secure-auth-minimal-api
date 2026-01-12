## Step 3A – Mapping Policy MFA/WebAuthn

### Scopo
Mappare WebAuthn nelle policy MFA esistenti (`RequireMfa`, `RequireRecentMfa`) e sugli endpoint sensibili.

### Attività
- Estendere `RequireMfa`/`RequireRecentMfa` per accettare esito WebAuthn (`session.MfaSatisfied` true).
- Aggiornare claim `amr`/`auth_time` in emissione token (incluso FIDO2) senza rompere TOTP.
- Applicare policy agli endpoint sensibili (come da MFA_STEPUP_PLAN):
  - Step-up: change-password/email, revoke sessioni, disable/reset MFA, password-reset/confirm.
  - Present MFA: mfa enable/setup, introspect (se protetto).
  - Non MFA: login/refresh/logout/me/sessions/health/live/ready/register/confirm-email.

### Sicurezza
- FIDO2 può soddisfare `RequireMfa`/`RequireRecentMfa` (documentare se “recent” non richiesto).
- Nessun downgrade automatico da FIDO2 a TOTP per privilegiati.

### Test (xUnit) da implementare
- Endpoint step-up: sessione con WebAuthn `MfaSatisfied=true` → 200; senza → 401/403.
- Claim `amr` corretto (pwd+fido2) e `auth_time` aggiornato.

### Note operative
- Policy centralizzate (filtri/authorize) e non check ad hoc.
- Aggiornare `RequireRecentMfa` per accettare FIDO2 se considerata sufficiente.
