# Proposta hardening sicurezza (solo bozza, non applicata)

Obiettivo: rafforzare i controlli HTTP e cookie in produzione, evitando di rompere i test/dev HTTP.

## Modifiche proposte
1) Header di sicurezza globali (solo fuori da Development):
   - HSTS: `UseHsts()` con max-age adeguato (es. 6 mesi) e includeSubDomains.
   - `UseHttpsRedirection()` in produzione.
   - Header fissi: `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-XSS-Protection: 0` (per disattivare modalità legacy), CSP minimale (es. `default-src 'none'; frame-ancestors 'none'; base-uri 'none'`) se non serve front-end.
   - Middleware leggero prima degli endpoint per aggiungere gli header solo in prod.

2) Cookie Secure obbligatorio fuori da Development:
   - In `Program.cs`, se `IHostEnvironment.IsProduction()` (o non Development) forzare `requireSecure = true` e magari loggare warning se è false.
   - In Dev/Tests lasciare `RequireSecure=false` per compatibilità con gli attuali test HTTP.

3) Validazioni config:
   - Se ambiente non Development e `Jwt:Issuer`/`Audience` non sono HTTPS, log warning o blocco avvio (opzionale).
   - Fail fast se `Cookie:RequireSecure=false` in prod.

## Test da aggiungere
- In ambiente “Production” simulato (config override) verificare che la risposta a `/health` includa gli header attesi (HSTS, X-Frame-Options, X-Content-Type-Options, CSP).
- Verificare che il Set-Cookie includa sempre `Secure` quando l’ambiente non è Development, anche se config tenta di disabilitare.
- In ambiente Development mantenere comportamento attuale (test esistenti su Secure/Non-Secure).

## Note di implementazione
- Aggiungere un middleware custom (es. `app.Use(async (ctx,next)=>{...})`) che inserisce gli header solo se `!env.IsDevelopment()`.
- Usare `app.UseHsts()` e `app.UseHttpsRedirection()` condizionati su ambiente.
- Integrare la logica del cookie Secure già in `Program.cs` leggendo `app.Environment`.
- Aggiornare i test di integrazione per coprire il caso Production simulato con base URL HTTP ma config/ambiente impostati: in tal caso l’API dovrebbe forzare il flag Secure; se si vuole essere rigorosi, si potrebbe far fallire l’avvio se non si usa HTTPS reale in prod (richiede adattare i test a usare HTTPS o a considerare fallback).
