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
- `StepUp_WithWebAuthn_Allows`: sessione con `MfaSatisfied=true` (FIDO2) su endpoint step-up → 200.
- `StepUp_WithoutMfa_Blocks`: sessione senza MFA → 401/403 sugli stessi endpoint.
- `AmrClaims_WebAuthn`: emissione token con FIDO2 → `amr` contiene `pwd,fido2` e `auth_time` valorizzato.

### Note operative
- Policy centralizzate (filtri/authorize) e non check ad hoc.
- Aggiornare `RequireRecentMfa` per accettare FIDO2 se considerata sufficiente.
- `MfaSatisfied` da leggere dalla sessione (`user_sessions` estesa in 1C) e propagare nel token/claims.
- Se si vuole “recent” anche per FIDO2, parametrizzare una finestra (es. 10 min); altrimenti documentare che FIDO2 soddisfa `RequireRecentMfa` sempre.
- Applicazione policy: usare `MapGroup("/webauthn")`/altri endpoint con `.RequireAuthorization("RequireMfa")` o `.RequireAuthorization("RequireRecentMfa")` sugli endpoint step-up.
