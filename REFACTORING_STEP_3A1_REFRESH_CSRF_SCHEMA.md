## Step 3A.1 - Schema/Repo/Model (refresh_csrf_hash)

**Obiettivo:** aggiungere il token CSRF di refresh al modello/DB/repository senza cambiare il contratto degli endpoint.

### Tasks
- Schema: aggiungere colonna `refresh_csrf_hash` a `refresh_tokens` (TEXT nullable).
- Modello: `Models/RefreshToken.cs` aggiunge proprietà `RefreshCsrfHash`.
- Repository: `Data/RefreshTokenRepository.cs` gestisce la colonna in Create/Get/Rotate.
- DbInitializer: migrazione per la nuova colonna (ALTER TABLE + eventuale indice se serve).

### Test
- Test di repository per:
  - Scrittura/lettura `refresh_csrf_hash`.
  - Rotazione: il campo viene copiato/aggiornato correttamente.
- `dotnet test` completo deve rimanere verde (nessun cambio di contratto degli endpoint).

### Come affrontarlo
- Implementare la colonna e aggiornare i mapper Dapper.
- Aggiungere test su `RefreshTokenRepository` per confermare la persistenza del nuovo campo.
- Non toccare ancora gli endpoint: contratto API invariato.
