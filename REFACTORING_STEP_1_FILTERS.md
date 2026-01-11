## Step 1 - Filtri e tipi base

**Obiettivo:** predisporre i mattoni compositivi (filtri e tipi) senza cambiare il comportamento degli endpoint.
**Stato attuale:** controlli di sessione/CSRF/MFA sparsi in vari endpoint e middleware; nessun filtro riusabile.
**Azione:** introdurre i componenti riusabili senza toccare gli endpoint.

- Middleware attuali da cui estrarre comportamento:
  - `Middleware/CookieJwtAuthMiddleware.cs`: popola `HttpContext.Items["session"]` con `UserSession` se `access_token` valido (idle timeout, revoca, ecc.).
  - `Middleware/CsrfMiddleware.cs`: applica CSRF su metodi unsafe, salta alcune route pubbliche; confronta header `X-CSRF-Token` con `session.CsrfToken` usando FixedTimeEquals.
- Endpoint che oggi dipendono da `HttpContext.Items["session"]` e controlli CSRF manuali: logout, logout-all, change-password, refresh, confirm-mfa, ecc.

- Aggiungi cartella `Filters/` con:
  - `SessionFilter`: legge `HttpContext.Items["session"]`, se assente 401.
  - `CsrfFilter`: verifica header CSRF (`X-CSRF-Token` vs `session.CsrfToken`), 403 su mismatch/assenza.
  - `MfaFilter`: verifica che la sessione abbia MFA confermato (o parametro livello), 401/403 se non soddisfatto.
- Aggiungi `SessionContext` record per esporre la sessione ai delegate endpoint (iniettata via filter/middleware).
- Aggiungi extension methods:
  ```csharp
  IEndpointConventionBuilder RequireSession(this IEndpointConventionBuilder e);
  IEndpointConventionBuilder RequireCsrf(this IEndpointConventionBuilder e);
  IEndpointConventionBuilder RequireMfa(this IEndpointConventionBuilder e);
  ```
- Non applicare ancora i filtri agli endpoint; solo wiring e test unitari dei filtri.
- Test attesi (unit):
  - `SessionFilter` → 401 se `Items["session"]` mancante; passa se presente.
  - `CsrfFilter` → 403 se header assente/errato; passa con token valido.
  - `MfaFilter` → 401/403 se sessione non MFA; passa se `MfaConfirmed=true`.

### Come affrontarlo
- Copiare la logica di `CookieJwtAuthMiddleware` e `CsrfMiddleware` in filtri riusabili, mantenendo lo stesso contratto (sessione in Items, header `X-CSRF-Token`, whitelist delle route se serve).
- Creare i filtri in una nuova cartella, con test unitari che simulano `HttpContext` senza toccare gli endpoint.
- Aggiungere gli extension methods ma non applicarli ancora: obiettivo è zero regressioni di comportamento.
