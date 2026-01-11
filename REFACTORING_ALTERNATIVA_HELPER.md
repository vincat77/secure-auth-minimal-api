## Approccio alternativo (meno intrusivo)

**Idea:** evitare filtri/endpoint filters e usare helper/extension dichiarativi dentro gli endpoint o con mini-builder, limitando i cambi di pipeline.

### Mattoni proposti
- Helper statici (es. in `EndpointGuards`):
  - `RequireSession(HttpContext ctx)` → restituisce sessione o `Results.Unauthorized()`.
  - `RequireCsrf(HttpContext ctx, UserSession session)` → valida header `X-CSRF-Token` vs `session.CsrfToken`, altrimenti `Results.Forbid()`.
  - `RequireMfa(UserSession session)` → verifica `MfaConfirmed`, altrimenti `Results.Forbid()`.
- Extension per endpoint protetti:
  ```csharp
  public static async Task<IResult> SecureGuard(HttpContext ctx, Func<UserSession, Task<IResult>> next)
  {
      var session = RequireSession(ctx);
      if (session is IResult res) return res; // Unauthorized
      var csrf = RequireCsrf(ctx, (UserSession)session);
      if (csrf is IResult res2) return res2; // Forbid
      return await next((UserSession)session);
  }
  ```
  Da usare così:
  ```csharp
  app.MapPost("/logout", ctx => SecureGuard(ctx, async session => {
      // logica dominio
      return Results.Ok();
  }));
  ```

### Vantaggi
- Nessun nuovo filtro globale/pipeline; riuso esplicito ma locale.
- Si può migrare endpoint per endpoint senza toccare middleware esistente.
- Riduce la duplicazione (chiama helper) ma l’ordine pipeline resta invariato.

### Piano minimale
1. Creare helper/guardie in una classe statica (es. `EndpointGuards`) con la stessa logica di `CookieJwtAuthMiddleware` e `CsrfMiddleware`.
2. Migrare un endpoint alla volta (logout, logout-all, change-password) sostituendo i check manuali con le guardie.
3. Estendere alle altre route sensibili (refresh, confirm-mfa, change-email) se si vuole, lasciando i pubblici invariati.
4. Aggiornare test per confermare codici 200/401/403 invariati; nessun cambio di pipeline.

### Rischi/mitigazioni
- Rischio basso: non si cambia l’host/middleware, solo si riutilizzano helper. Migrare per piccoli lotti e testare CSRF/sessione per ogni endpoint toccato.
