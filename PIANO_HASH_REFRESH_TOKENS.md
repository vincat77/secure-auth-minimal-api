# Piano di azione – Hash/HMAC per refresh token
Obiettivo: evitare storage in chiaro dei refresh token memorizzando solo l’HMAC/hash in DB, con compatibilità e test aggiornati.

## Obiettivi
- Salvare in DB solo hash/HMAC dei refresh token (no token in chiaro).
- Aggiornare flussi di creazione/lookup/rotazione/revoca per usare l’hash.
- Migrazione compatibile con DB esistente e test aggiornati.
- Non loggare mai il token in chiaro (solo hash/metadata).

## Passi
1) Schema e configurazione
   - Aggiungere colonna `token_hash` a `refresh_tokens` (UNIQUE, indicizzata).
   - (Opzionale) chiave HMAC da config: `Refresh:HmacKey` o reuse `Jwt:SecretKey` se documentato (meglio chiave separata, 32+ char).
   - Indici: UNIQUE(token_hash); mantenere idx user/session/device.
   - Backward compat: mantenere colonna `token` solo per migrazione/backfill, da deprecare.
2) Servizi/repository
   - In `RefreshTokenRepository` salvare hash/HMAC del token e non il token in chiaro.
   - Lookup/rotate/revoke basati su `token_hash`; evitare confronti sul token in chiaro.
   - Gestire rotazione creando nuovo hash e marcando il vecchio revoked.
   - Utility: metodo `ComputeHash(string token)` riutilizzato nei flussi; usare HMACSHA256 con key da config.
   - Fallback compat (fase transizione): se `token_hash` nullo, calcolare hash on-the-fly dal token legacy e aggiornare la riga.
3) Program.cs (flow)
   - In login/confirm-mfa/refresh/logout/logout-all usare il nuovo path: generare token, calcolare hash, salvare hash, verificare hash sul cookie.
   - Evitare log del token in chiaro.
   - In /refresh validare su hash; se `token_hash` mancante ma `token` presente, backfill hash e proseguire (flag temporaneo).
4) Migrazione/compat
   - Backfill: su prima rotazione o su un job di migrazione, popolare `token_hash` dai token esistenti.
   - Fase di transizione: accetta lookup su `token_hash`, con fallback temporaneo su `token` se `token_hash` nullo (da rimuovere dopo rollout).
   - Dopo rollout: colonna `token` può essere azzerata o droppata; rimuovere il fallback.
5) Test
   - Aggiornare test integration per login/refresh/logout/logout-all con hash.
   - Aggiungere test che il token non appaia nel DB (solo hash) e che l’HMAC cambi se cambia il segreto.
   - Test compat: token legacy senza hash viene backfillato al primo uso /refresh.
   - Test sicurezza: cookie refresh rubato + DB leak -> hash non impedisce riuso, ma riduce impatto del leak DB.
6) Documentazione
   - Note su rollout: richiede chiave HMAC stabile e backfill; in prod eliminare token in chiaro dopo migrazione.

## Dettaglio implementativo per file
- `Data/DbInitializer.cs`
  - `EnsureColumn(refresh_tokens, "token_hash")`; creare indice UNIQUE `idx_refresh_tokens_token_hash`.
  - Se presente solo `token` (legacy), nessun drop, solo add column + indice.
- `Models/RefreshToken.cs`
  - Aggiungere proprietà `TokenHash` (string?); mantenere `Token` come uso runtime (non mappato al DB) o renderlo `[JsonIgnore]` se necessario.
- `Services/RefreshTokenHasher` (nuova classe)
  - Costruttore legge `Refresh:HmacKey` (preferito) o fallback a `Jwt:SecretKey`; fail-fast se <32 char.
  - Metodo `Compute(string token)` → `string` (es. Base64Url o hex) usando HMACSHA256.
- `Data/RefreshTokenRepository.cs`
  - `CreateAsync/RotateAsync`: salvare `token_hash` (Compute) e NON il token in chiaro; se si mantiene colonna `token`, settarla null/opzionale per transizione.
  - `GetByTokenAsync(string token)`: calcolare hash, query su `token_hash`; fallback compat (solo per rollout) se hash nullo → query su `token`, calcolare hash, aggiornare riga con hash e null token.
  - `RevokeByTokenAsync(string token)`: idem, lavorare su hash; eventuale fallback legacy.
  - `RevokeAllForUserAsync`: invariato.
- `Program.cs`
  - In login/confirm-mfa: generare refreshToken, calcolare hash via hasher service, passare `TokenHash` al repository, evitare log del token.
  - In `/refresh`: leggere cookie, calcolare hash, fare lookup su hash; se record legacy senza hash, backfill hash e continuare; ruotare usando hash.
  - In `/logout` e `/logout-all`: se cookie presente, calcolare hash e revocare via hash (e backfill se serve).
- `tests/SecureAuthMinimalApi.Tests`
  - Aggiornare query dirette al DB per usare `token_hash` (non `token`) o per verificare assenza del token in chiaro.
  - Aggiungere test compat: refresh legacy senza hash viene backfillato al primo uso.
  - Aggiungere test che `refresh_tokens.token` sia NULL/vuoto e `token_hash` non nullo dopo login/refresh.
- `appsettings*.json`
  - Documentare `Refresh:HmacKey` (se usato) e la lunghezza minima; in dev si può riusare Jwt:SecretKey ma va esplicitato.

## Note di rollout/migrazione
- In sviluppo (no dati prod): puoi applicare la modifica direttamente, senza compat, settando `token_hash` e azzerando/droppando `token` subito dopo aver aggiornato codice e schema.
- Se vuoi comunque un passaggio graduale:
  - Fase 1: aggiungi colonna `token_hash` + indice, aggiorna codice per scrivere hash e lascia fallback se `token_hash` manca.
  - Fase 2: esegui backfill automatico su `/refresh` o job batch; verifica che tutte le righe abbiano `token_hash` non nullo.
  - Fase 3: rimuovi fallback e azzera/drop colonna `token`; conferma che query/test usino solo hash.
