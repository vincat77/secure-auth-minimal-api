## Piano d'azione MFA / Step-Up (ASVS L3)

### Obiettivo
Imporre MFA dove conta per ASVS L3, con tre policy semplici:
1) `Authenticated`
2) `RequireMfa` (MFA presente nella sessione)
3) `RequireRecentMfa(X min)` (MFA eseguita negli ultimi X minuti, es. 5–10)

### Endpoint che richiedono **MFA recente** (step-up)
- `POST /change-password`
- `POST /change-email`
- `POST /password-reset/confirm`
- `POST /mfa/disable`
- `POST /mfa/reset`
- `POST /sessions/revoke-all`

Regola: applicare `RequireRecentMfa(X min)`.

### Endpoint **privilegiati** (se presenti ruoli/admin)
- `POST /admin/*`
- `PUT /users/{id}`
- `POST /users/{id}/lock|unlock`
- `POST /users/{id}/roles`

Regola: `RequireMfa` anche al login, non solo step-up.

### Endpoint che richiedono **MFA presente** (una volta per sessione)
- `POST /mfa/enable`
- `POST /mfa/verify` (setup)
- `POST /email/confirm` (opzionale ma consigliato)

Regola: `RequireMfa` (non serve recente).

### Endpoint **senza MFA** (niente friction extra)
- `POST /login`
- `POST /refresh`
- `POST /logout`
- `GET /me`
- `GET /health`

### Mappatura sintetica
| Endpoint                      | Policy            |
| ----------------------------- | ----------------- |
| cambio password/email         | RequireRecentMfa  |
| revoke all session            | RequireRecentMfa  |
| disable/reset mfa             | RequireRecentMfa  |
| admin/utenti privilegiati     | RequireMfa        |
| mfa enable/setup              | RequireMfa        |
| resto auth protetto           | Authenticated     |

### Note di implementazione
- Introdurre una proprietà di sessione (es. `MfaLastConfirmedUtc`) e un check `IsRecent(now, Xmin)`.
- Centralizzare con filtri/policy (es. `RequireMfa`, `RequireRecentMfa`) invece di check ad hoc.
- Parametrizzare X minuti (es. `Mfa:RecentMinutes = 5`).

### Test minimi
- Step-up: login + MFA, poi cambio password senza MFA recente → 401/403; con MFA recente → 200.
- Admin: login senza MFA per account privilegiato → rifiutato; con MFA → ok.
- Rinnovo: MFA scaduta (oltre X min) blocca endpoint step-up.

### Perché allinea a ASVS L3
- Copre V2/V3 con step-up reale, minimo set di policy, auditabile e spiegabile.
