# Piano: Cifratura dei refresh token a riposo

Obiettivo: proteggere i valori dei refresh token (e device_id se necessario) nel DB, così che un dump non consenta il riutilizzo dei token.

## Approccio tecnico
- Usare `IDataProtectionProvider` (già presente per TOTP) per cifrare/decrittare i refresh token.
- Cifrare solo il campo `token` (valore segreto). Lasciare device_id in chiaro: non è segreto, ma opzionale se si vuole offuscare anche quello.
- Applicare la cifratura in fase di insert/rotate e la decifratura in fase di read (`GetByTokenAsync`).
- Per le query di lookup, mantenere una colonna derivata per il matching. Opzioni:
  - (A) Salvare anche un hash/lookup: memorizzare `token_hash` (SHA-256) e fare lookup su hash, mentre `token` cifrato è usato solo per set-cookie/rotazione.
  - (B) Cifrare con protezione deterministica per lookup diretto. **Sconsigliato** con DP di default: non deterministica. Preferire (A).
- Gestire la rotazione/rollback senza rompere compatibilità per record esistenti: se `token_hash` è null, migrare on-the-fly al primo accesso.

## Passi operativi
1) Schema
   - Tabella `refresh_tokens`: aggiungere colonna `token_hash TEXT UNIQUE` (index).
2) Servizi
   - Nuovo servizio `RefreshTokenProtector` (DataProtection) per cifrare/decrittare il token in DB.
3) Repository
   - In insert/rotate: calcolare hash SHA-256 del token in chiaro, salvare `token_hash`, salvare `token` cifrato.
   - In lookup: accettare token in chiaro, calcolare hash, cercare per `token_hash`. Se record legacy senza hash, decifrare `token`, verificare match e migrare hash.
4) Program.cs
   - Adeguare la creazione/rotazione refresh token a usare la protezione e l’hash.
   - Set-Cookie continua a usare il token in chiaro generato runtime.
5) Test xUnit
   - Login remember → DB contiene token cifrato e token_hash valorizzato; lookup funziona con token in chiaro.
   - Refresh rotazione → vecchio token revocato, nuovo cifrato/hash settato.
   - Record legacy (token in chiaro, hash null) → primo accesso genera hash e continua a funzionare (test di migrazione on-the-fly, se implementato).
6) Dev/compatibilità
   - Nessun cambiamento per i client: i cookie restano token in chiaro (HttpOnly). Cifratura è solo a riposo.

## Note
- L’hash deve essere su token originale prima della cifratura.
- DataProtection produce output con IV casuale: non usarlo per matching; hash dedicato è necessario.
- Valutare lunghezza colonne per evitare truncate (Base64Url, SHA-256 Base64/hex). Usare es. hex 64 char.
