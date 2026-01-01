# Piano aggiunta disattivazione MFA (/mfa/disable)

Obiettivo: endpoint protetto che rimuove il TOTP dall’utente loggato, con CSRF, e test xUnit.

## Passi
1) API endpoint
   - POST `/mfa/disable`, protetto da sessione + CSRF.
   - Carica l’utente dal `UserRepository`, setta `totp_secret = null`.
   - Se già nullo, restituisce 204 o 200 ok.
   - Risposte: 200 ok, 401/403 gestiti da middleware, 404 se utente non trovato (edge raro).

2) Repository
   - Aggiungere metodo `ClearTotpSecretAsync(userId)` in `UserRepository` che setta il campo a NULL (cifratura non necessaria perché nullo).

3) Test xUnit
   - Setup: registra utente, login, `/mfa/setup`, verifica che in DB ci sia un valore cifrato.
   - Chiamata `/mfa/disable` con CSRF e cookie -> 200.
   - Verifica DB: `totp_secret` è NULL.
   - Verifica che login senza TOTP torni a funzionare senza 401.

4) WinForms (opzionale, dopo API)
   - Aggiungere bottone “Disattiva MFA” che chiama `/mfa/disable` con CSRF, aggiorna log/stato.

5) Build/test
   - Eseguire `dotnet test` e (per WinForms) `dotnet build clients/WinFormsClient/WinFormsClient.csproj` se il bottone viene aggiunto.
