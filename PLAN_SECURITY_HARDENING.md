# Piano hardening sicurezza (seed/demo, JWT secret, DataProtection, artefatti)

## Obiettivo
Ridurre rischi di ambienti non demo: disattivare seed demo per default, bloccare secret JWT placeholder, persistere le chiavi DataProtection, ignorare artefatti runtime (db/log).

## Step proposti (ordine esecuzione)

1) Seed demo sicuro (obbligatorio)  
   - File: `Data/DbInitializer.cs`.  
   - Azione: `Seed:Enabled` default `false`; opzionale gate `IHostEnvironment.IsDevelopment()` se abilitato.  
   - Esito atteso: in ambienti non-dev non viene creato l’utente demo senza opt-in esplicito.

2) Validazione secret JWT (obbligatorio)  
   - File: `Program.cs`.  
   - Azione: in non-Development, fail-fast se `Jwt:SecretKey` è placeholder (`CHANGE_ME`) o troppo corto/banale.  
   - Esito atteso: l’app non parte in prod con secret debole.

3) Persistenza chiavi DataProtection (fortemente consigliata)  
   - File: `Program.cs`.  
   - Azione: aggiungere `.PersistKeysToFileSystem(<percorso sicuro>)` e opzionale `.SetApplicationName("SecureAuthMinimalApi")`.  
   - Esito atteso: restart/redeploy non invalida payload protetti (es. segreti MFA cifrati).

4) Repo hygiene (consigliata)  
   - File: `.gitignore` + pulizia working tree.  
   - Azione: ignorare `auth.db`, `logs/`, altri artefatti runtime; rimuovere eventuali file già tracciati.  
   - Esito atteso: nessun artefatto sensibile nel repo/zip.

## Note
- Tenere i 4 step separati per commit/rollback facile.  
- Validare in un ambiente non-dev che l’app parte solo con secret forte e che il seed demo resta disattivato salvo opt-in.  
- DataProtection: scegliere percorso persistente condiviso tra istanze (es. volume/dir condivisa in container).
