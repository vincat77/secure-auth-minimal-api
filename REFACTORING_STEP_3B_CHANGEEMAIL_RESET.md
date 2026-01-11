## Step 3B - Filtri su change-email e password reset confirm

**Obiettivo:** applicare i filtri agli endpoint utente sensibili, mantenendo la semantica attuale (token vs sessione).
**Stato attuale:** `ChangeEmailEndpoints` valida sessione/CSRF manualmente; `PasswordResetEndpoints` (confirm) è token-based senza session/CSRF.
**Azione:** applicare `RequireSession`/`RequireCsrf` dove già presenti manualmente; evitare regressioni sul reset token-based.

Ambito:
- `ChangeEmailEndpoints` → `.RequireSession().RequireCsrf().RequireMfa()` (se l’attuale flusso richiede MFA); rimuovere controlli duplicati.
- `PasswordResetEndpoints` (confirm) → **non** applicare filtri se resta token-only; applicare solo se si decide di richiedere sessione/CSRF (valutare impatto).

Attività:
- Annotare `ChangeEmailEndpoints` con filtri e togliere check manuali di sessione/CSRF/MFA.
- Lasciare `PasswordReset confirm` invariato salvo decisione contraria; in tal caso aggiornare anche la doc/API contract.

Test da eseguire/adattare:
- `ApiTests` su change-email (200/401/403 invariati) con CSRF/MFA.
- Se si tocca password reset confirm: test end-to-end reset (token valido/errato/scaduto) per evitare regressioni; nessun nuovo requisito di sessione/CSRF salvo scelta esplicita.

### Come affrontarlo
- Migrare prima change-email: applicare filtri e rimuovere controlli duplicati, poi eseguire i test di change email già presenti (e aggiungere casi CSRF/MFA negativi).
- Per password reset confirm: default è non toccare; se richiesto, applicare filtri in modo opzionale e aggiornare i test di reset per riflettere i nuovi prerequisiti.
