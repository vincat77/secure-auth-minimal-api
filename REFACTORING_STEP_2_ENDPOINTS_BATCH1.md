## Step 2 - Applicare filtri (batch 1)

**Obiettivo:** iniziare la migrazione sugli endpoint più semplici riducendo duplicazioni di session/CSRF.
**Stato attuale:** logout/logout-all/change-password eseguono manualmente check di sessione/CSRF.
**Azione:** applicare i filtri agli endpoint più semplici/sensibili, rimuovendo controlli duplicati.

Ambito:
- `LogoutEndpoints` → `.RequireSession().RequireCsrf()`
- `LogoutAllEndpoints` → `.RequireSession().RequireCsrf()`
- `ChangePasswordEndpoints` → `.RequireSession().RequireCsrf()`

Attività:
- Annotare gli endpoint con le extension dei filtri.
- Rimuovere i controlli manuali di session/CSRF già coperti dal filtro.
- Verificare che il middleware `CookieJwtAuthMiddleware` sia registrato prima dei filtri (ordine pipeline invariato).
- Note dai file attuali:
  - `LogoutEndpoints`: oggi legge sessione da `ctx.GetRequiredSession()` e richiede header CSRF manuale; pulisce cookie access/refresh/device.
  - `LogoutAllEndpoints`: stessa logica, revoca refresh di tutti i device, usa cookie settings da config.
  - `ChangePasswordEndpoints`: valida sessione, check CSRF tramite header, gestisce rotazione sessione/refresh.
  - `CsrfMiddleware` già applica check per POST/PUT/PATCH/DELETE; i filtri dovranno coordinarsi (evitare doppio check).

Test da eseguire/adattare:
- `ApiTests` su logout/logout-all/change-password (200/401/403 invariati).
- Test specifici CSRF (403 se header mancante/errato) sugli endpoint migrati.
- Eventuali test dedicati per `RequireSession` su questi endpoint (401 se cookie/sessione assente).

### Come affrontarlo
- Applicare le extension `.RequireSession().RequireCsrf()` ai tre endpoint, rimuovendo i check manuali di sessione/CSRF per evitare doppioni.
- Verificare che la pipeline middleware resti: CookieJwtAuth → CsrfMiddleware → Endpoint (con filtri che devono risultare idempotenti rispetto al middleware o portare alla rimozione del middleware in step successivo).
- Aggiornare i test esistenti (logout/logout-all/change-password) per confermare codici 200/401/403 invariati e aggiungere casi di CSRF mancante/errato.
