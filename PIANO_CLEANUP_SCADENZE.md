# Piano di azione - Cleanup record scaduti (sessioni/refresh/challenge)
Obiettivo: introdurre un background service che elimina periodicamente dal DB i record scaduti o revocati (user_sessions, refresh_tokens, mfa_challenges) per ridurre superficie di attacco e crescita dati.

## Obiettivi
- Rimuovere sessioni scadute o revocate, refresh scaduti/revocati e challenge MFA scaduti/usati.
- Configurazione tramite appsettings (abilitazione, intervallo, batch).
- Impatto minimo su prestazioni e nessuna dipendenza esterna.

## Passi
1) Config
   - Sezione `Cleanup`: `Enabled` (bool), `IntervalSeconds` (default 300), `BatchSize` opzionale.
   - Documentare in `appsettings.guida.md`.
   - (Opzionale) `MaxIterationsPerRun` per limitare i batch in un singolo ciclo.
2) Background service
   - Nuovo `ExpiredCleanupService` derivato da `BackgroundService`.
   - Delay basato su `IntervalSeconds`; salta se `Enabled=false`.
   - Catch/log eccezioni, log info sui numeri eliminati.
3) Repository metodi cleanup
   - `SessionRepository`: `DeleteExpiredAsync` (expires_at_utc < now OR revoked_at_utc non nullo).
   - `RefreshTokenRepository`: `DeleteExpiredAsync` (expires_at_utc < now OR revoked_at_utc non nullo).
   - `MfaChallengeRepository`: `DeleteExpiredAsync` (expires_at_utc < now OR used_at_utc non nullo).
   - SQL con LIMIT su batch per evitare lock lunghi; eventuale indice su expires_at_utc in `DbInitializer`.
4) Wire-up
   - Registrare il background service in `Program.cs`.
   - Leggere config `Cleanup:*`; loggare stato abilitato/disabilitato all'avvio.
5) Test
   - Integrazione: creare record scaduti e verificare che il cleanup li rimuova dopo il tick (intervallo basso).
   - Test `Enabled=false`: nessuna eliminazione.
   - Test batch: con `BatchSize` piccolo, cleanup procede a passi (ancora record fino al run successivo).
   - Per tipo: sessioni scadute/revocate, refresh scaduti/revocati, challenge scadute/usate; record validi restano.
   - DB vuoto: il servizio non lancia eccezioni.
   - `MaxIterationsPerRun` (se usato) interrompe dopo N batch.
   - Indici expires: creazione idempotente (non fallisce se gia' esistono).
   - Concorrenza: cleanup non deve cancellare record freschi (date future).
   - Logging: il servizio logga info/error ma non interrompe l'host su errore singolo.
   - E2E: login/refresh, tick cleanup; i record validi restano, quelli scaduti spariscono.
   - Idle timeout + cleanup: sessioni con last_seen vecchio (oltre idle) vengono cancellate e /me torna 401.
   - Challenge MFA: challenge scaduta/usata viene rimossa, una attiva resta.
   - Fault injection: conn string errata -> l'app resta up e il servizio logga l'errore.
6) Doc
   - Aggiornare `DESCRIZIONE_SOLUTION.md` e `appsettings.guida.md` con la sezione Cleanup (dev/prod).
   - Nota: in prod usare intervallo adeguato; in dev/test ridurre per velocita'.
