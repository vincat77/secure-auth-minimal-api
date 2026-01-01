# Piano: Idle Timeout e notifiche scadenza sessione

Obiettivo: aggiungere scadenza per inattività (idle timeout) lato server e informazioni di scadenza residue per il client. Manteniamo la scadenza assoluta già presente.

## Target
- Idle timeout configurabile (es. `Session:IdleMinutes`).
- Revoca sessione se `now - last_seen_utc > IdleTimeout`.
- Aggiornamento `last_seen_utc` ad ogni richiesta autenticata.
- Header informativi opzionali (`X-Session-Expires-At`, `X-Session-Idle-Remaining`) per il client.

## Passi tecnici
1) **Schema DB**
   - Aggiungere colonna `last_seen_utc` su `user_sessions` (default = created_at_utc).
   - Migrazione idempotente in `DbInitializer`.

2) **Modello e repo**
   - Estendere `UserSession` per includere `LastSeenUtc`.
   - Aggiornare `SessionRepository` per leggere/scrivere `last_seen_utc` e aggiungere metodo `UpdateLastSeenAsync(sessionId, now)`.

3) **Config**
   - `Session:IdleMinutes` (default es. 30). Disabilitabile con valore <=0.

4) **Middleware/flow**
   - In `CookieJwtAuthMiddleware` (dopo aver caricato la sessione), verificare se idle timeout è attivo:
     - Se `now - last_seen > idleTimeout`: revocare sessione e NON settare ctx.Items["session"] → risponde 401 a endpoint protetti.
     - Altrimenti, aggiornare `last_seen_utc` (opzionale: solo se >1m di drift per ridurre scritture).
   - Impostare header di stato: `X-Session-Expires-At`, `X-Session-Idle-Remaining` (se sessione valida e idle attivo).

5) **Test xUnit**
   - Idle attivo: creare sessione con last_seen vecchio > timeout → richiesta /me ritorna 401 e sessione marcata revoked (o non valida).
   - Idle attivo, richiesta entro timeout: /me OK e last_seen aggiornato.
   - Idle disabilitato (IdleMinutes<=0): comportamento invariato.
   - Header informativi presenti su /me con sessione valida.

6) **UI (opzionale)**
   - WinForms può leggere header e aggiornare countdown; per ora non necessario.

7) **Cleanup**
   - (Opzionale) job/manuale per revocare sessioni scadute/idle vecchie; non essenziale per il primo step.
