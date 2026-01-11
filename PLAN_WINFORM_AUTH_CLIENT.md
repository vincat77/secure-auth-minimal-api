# Piano: WinFORM_AUTH_Client (WinForms + SecureAuthClient)

## Obiettivo
Nuovo progetto WinForms (`WinFORM_AUTH_Client`) compatibile con designer VS2022 che usa `SecureAuthClient` per esercitare il flusso completo MFA:
1) Crea utente
2) Conferma email
3) Login
4) Setup MFA e mostra `otpauth://...` in textbox
5) Logout
6) Login
7) Conferma MFA con TOTP inserito dall’utente in un’altra textbox

UI minima: un bottone per l’intero flow + due textbox (otpauth, totp input).

## Passi
1. **Setup progetto**
   - Creare WinForms project `WinFORM_AUTH_Client` (net8.0-windows, UseWindowsForms=true, EnableWindowsTargeting=true).
   - Aggiungere riferimento a `clients/SecureAuthClient/SecureAuthClient.csproj`.
   - Aggiungere form principale `MainForm` con file `.Designer.cs` standard VS.

2. **UI (Designer-friendly, senza FlowLayout/TableLayout)**
   - Controlli minimi:
     - TextBox `txtBaseUrl` (default `https://localhost:52899`).
     - TextBox `txtOtpauth` (readonly) per mostrare la URI MFA.
     - TextBox `txtTotp` per inserire il codice TOTP manuale.
     - Button `btnRunFlow` (“Esegui flow MFA”).
     - (Opzionale) TextBox multiline `txtLog` per log operativi.
   - Impostare `FormBorderStyle`, `StartPosition`, `AutoScaleMode` standard; nessun codice auto-generato manuale (tutto via InitializeComponent).
   - **Layout**: posizionare i controlli con coordinate/ancoraggi standard; evitare FlowLayoutPanel e TableLayoutPanel (vietati).

3. **Flow end-to-end (click btnRunFlow)**
   - In handler click, eseguire in sequenza (con await):
     1. **Register**: utente random (es. `flow-{Guid}`), pwd forte, email random.
     2. **Confirm-email**: chiamare `/confirm-email` con token restituito da register.
     3. **Login**: via `SecureAuthApiClient.LoginAsync` (remember=true).
     4. **Setup MFA**: chiamare `/mfa/setup` con CSRF dal login; salvare `secret` e `otpauthUri`, mostrarli in `txtOtpauth`.
     5. **Logout**: `LogoutAsync`.
     6. **Login**: aspettarsi `mfa_required` e `challengeId`.
     7. **Confirm-MFA**: leggere `txtTotp.Text`, chiamare `ConfirmMfaAsync(challengeId, totp, rememberMe:true)`.
     8. **/me**: chiamare `MeAsync` per verificare 200 e mostrare info user/sessione (in `txtLog`).
   - Gestione errori: se una fase fallisce, loggare in `txtLog` e interrompere.

4. **Gestione token/cookie**
   - Riutilizzare `SecureAuthApiClient` con `HttpClientHandler` (CookieContainer).
   - Non gestire manualmente CSRF/refresh header: il client lo fa già.
   - Per `/mfa/setup` usare `HttpClient` condiviso dal client (o esporre metodo wrapper) per includere cookie e header `X-CSRF-Token`.

5. **Compatibilità designer**
   - Tenere la logica nel code-behind di `MainForm.cs` (partial) e non toccare il `.Designer.cs` manualmente.
   - Aggiungere metodi helper minimi, nessuna modifica a InitializeComponent generato da VS.

6. **Test manuale**
   - Avviare API su `https://localhost:52899`.
   - Eseguire WinFORM_AUTH_Client, premere “Esegui flow MFA”, copiare il codice TOTP dall’app Authenticator in `txtTotp`, ripremere il bottone (o step interno che attende input) per conferma.
   - Verificare `/me` 200 e log finale.

7. **Pulizia**
   - Aggiornare tag (`tools/update-tags.ps1`).
   - Nessun test automatico richiesto.
