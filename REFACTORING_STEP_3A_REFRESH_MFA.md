## Step 3A - Filtri su refresh e confirm-mfa

**Obiettivo:** applicare i filtri compositivi agli endpoint di rotazione sessione/refresh e conferma MFA, senza alterare la semantica attuale.
**Stato attuale:** `RefreshEndpoints` non richiede sessione, crea nuova sessione+CSRF da refresh/device cookie; `ConfirmMfaEndpoints` valida challenge e crea nuova sessione, con cookie access/refresh/device e nuovo CsrfToken.
**Esito prova:** applicare `RequireCsrf` ha causato 401/Unauthorized perché il filtro richiede la sessione (non presente su refresh/confirm-mfa whitelisted dal CsrfMiddleware) e l’header CSRF non è inviato in questi flow. Per evitare regressioni i filtri CSRF vanno evitati qui finché non si progetta un check CSRF specifico per refresh.
**Azione attuale:** lasciare refresh/confirm-mfa senza filtri; se in futuro si vuole CSRF, servono filtri dedicati che non richiedano sessione ma usino il binding refresh/device.

Ambito:
- `RefreshEndpoints` → attualmente nessun filtro; eventuale futuro filtro CSRF deve essere sessionless e compatibile con la whitelist attuale del middleware.
- `ConfirmMfaEndpoints` → idem; crea nuova sessione, oggi è whitelisted dal middleware CSRF.

Attività:
- Non applicare filtri ora; mantenere la logica di dominio: rotazione refresh, creazione sessione, emissione cookie/SameSite/RequireSecure, CsrfToken nuovo.
- Se si introduce un filtro futuro, non deve richiedere sessione; deve validare l’header solo se fornito e restare compatibile con refresh/device cookie.

Test da eseguire/adattare:
- `ApiTests` su refresh e confirm-mfa devono restare verdi (200 attesi nei flow validi).
- Se si aggiunge un filtro dedicato, prevedere test per CSRF opzionale su refresh sessionless.
- Verifica cookie/SameSite/RequireSecure invariati.

### Come affrontarlo
- Per `RefreshEndpoints`: lasciare senza filtri; se si vuole CSRF, progettare un filtro che usi refresh/device binding (sessionless) o mantenere la whitelist del middleware.
- Per `ConfirmMfaEndpoints`: lasciare senza filtri; eventuale CSRF deve essere compatibile con la creazione di nuova sessione e assenza di sessione precedente.
- Priorità: evitare regressioni; valutare filtri solo dopo aver definito uno schema CSRF sessionless per refresh/MFA.
