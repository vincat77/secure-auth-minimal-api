# Piano aggiunta endpoint health/ready

Obiettivo: introdurre endpoint separati per liveness e readiness con check DB/config chiave JWT.

## Passi
1) Endpoint /live
   - Restituisce 200 con payload minimale `{ ok: true }`.
   - Nessun check esterno, solo per liveness.

2) Endpoint /ready
   - Esegue ping DB (apre connessione, SELECT 1).
   - Verifica che `Jwt:SecretKey`, `Jwt:Issuer`, `Jwt:Audience` siano presenti e validi (lunghezza >=32 per la secret).
   - Restituisce 200 se tutti i check passano; 503 con dettagli minimali se falliscono.
   - Timeout breve sul ping.

3) Wiring
   - Aggiungere i due endpoint in Program.cs (non richiedono auth/CSRF).
   - Usare lo stesso SessionRepository/UserRepository/conn string per il ping.

4) Test da aggiungere
   - /live restituisce 200 sempre.
   - /ready OK con config valida e DB raggiungibile.
   - /ready 503 se manca Jwt:SecretKey (config override in test) o se il DB è irraggiungibile (conn string invalida).
   - Assicurarsi che i test esistenti restino invariati.

5) Note
   - Ping DB: `SELECT 1;` con timeout breve.
   - Risposte errori: `{ ok: false, error: "db_unreachable" | "invalid_config" }`.
