## Step 3A.2 - Emissione token CSRF di refresh

**Obiettivo:** generare e restituire il token CSRF di refresh quando si emette/ruota il refresh token, senza ancora richiederlo in `/refresh`.

### Tasks
- Generazione: RNG 32 byte Base64Url, hash SHA256 (hex) salvato in `refresh_csrf_hash`.
- Endpoint:
  - `LoginEndpoints`: quando crea il refresh token, genera anche `refresh_csrf_token` e lo include nella response JSON (almeno in dev/test).
  - `ConfirmMfaEndpoints`: stesso pattern quando emette refresh token dopo MFA.
  - `RefreshEndpoints`: su rotazione, genera nuovo token CSRF di refresh e lo restituisce nella response.
- Risposta: aggiungere campo (es. `refreshCsrfToken`) nella response degli endpoint che emettono refresh.

### Test
- Aggiornare i test di login/confirm-mfa/refresh per verificare la presenza del nuovo campo nella response (dev/test).
- `dotnet test` deve restare verde: `/refresh` non richiede ancora l’header.

### Come affrontarlo
- Usare lo stesso helper RNG dei refresh (Base64Url 32 byte) e un helper per hash (SHA256 hex).
- Salvare solo hash in DB (`refresh_csrf_hash`), mai il token in chiaro.
- Restituire il token in chiaro nella response per i test; documentare che in prod potrebbe essere omesso.
