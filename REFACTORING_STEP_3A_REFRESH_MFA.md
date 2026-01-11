## Step 3A - Filtri su refresh e confirm-mfa

**Obiettivo:** applicare i filtri compositivi agli endpoint di rotazione sessione/refresh e conferma MFA, senza alterare la semantica attuale.
**Stato attuale:** `RefreshEndpoints` non richiede sessione, crea nuova sessione+CSRF da refresh/device cookie; `ConfirmMfaEndpoints` valida challenge e crea nuova sessione, con cookie access/refresh/device e nuovo CsrfToken.
**Azione:** valutare e applicare `RequireCsrf` e/o `RequireSession` dove opportuno, rimuovendo controlli duplicati.

Ambito:
- `RefreshEndpoints` → decidere se richiede solo `RequireCsrf` (per cookie-based) o anche `RequireSession` (se si vuole binding alla sessione esistente). Evitare `RequireMfa`.
- `ConfirmMfaEndpoints` → può usare `RequireCsrf` se si vuole enforce header oltre al middleware; non richiede sessione pre-esistente (crea nuova).

Attività:
- Annotare gli endpoint con i filtri scelti; eliminare controlli manuali di sessione/CSRF sovrapposti.
- Mantenere invariata la logica di dominio: rotazione refresh, creazione sessione, emissione cookie/SameSite/RequireSecure, CsrfToken nuovo.

Test da eseguire/adattare:
- `ApiTests` su refresh e confirm-mfa (codici 200/401/403 invariati).
- Test filtri: CSRF mancante/errato → 403, sessione richiesta (se applicata) → 401.
- Verifica cookie/SameSite/RequireSecure invariati.

### Come affrontarlo
- Per `RefreshEndpoints`: applicare `RequireCsrf` solo se non introduce regressioni (oggi CsrfMiddleware esclude /refresh); valutare `RequireSession` solo se si vuole rendere refresh dipendente da sessione. Aggiornare i test in base alla scelta.
- Per `ConfirmMfaEndpoints`: applicare `RequireCsrf` se si decide di imporre header; lasciare invariata l’assenza di `RequireSession` perché la sessione viene creata qui. Rimuovere eventuali check CSRF duplicati.
- Eseguire i test dedicati e confermare che i codici di risposta e le opzioni cookie non cambino.
