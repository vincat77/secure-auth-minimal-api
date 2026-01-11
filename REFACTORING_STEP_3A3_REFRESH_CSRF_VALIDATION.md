## Step 3A.3 - Validazione CSRF su /refresh (double-submit)

**Obiettivo:** richiedere header `X-Refresh-Csrf` su `/refresh`, confrontare con l’hash salvato e rispondere 403 su mismatch.

### Tasks
- Endpoint `/refresh`:
  - Leggere header `X-Refresh-Csrf`.
  - Se assente/vuoto → 403.
  - Confrontare hash(header) con `refresh_csrf_hash` del token (FixedTimeEquals); se diverso → 403.
  - Altrimenti proseguire come oggi.
- Rotazione: in response restituire il nuovo `refreshCsrfToken` insieme ai cookie refresh/device.

### Test
- Nuovi test xUnit (ApiTests):
  - `Refresh_missing_csrf_header_returns_403`.
  - `Refresh_invalid_csrf_header_returns_403`.
  - Happy path aggiornato: invia header corretto, 200, nuovo token restituito.
  - Device/UA mismatch restano 401 come oggi.

### Come affrontarlo
- Riutilizzare l’hash SHA256 hex e `CryptographicOperations.FixedTimeEquals`.
- Non introdurre dipendenza da sessione; resta un flusso sessionless.
- Aggiornare i test esistenti per includere l’header; aggiungere casi negativi.
