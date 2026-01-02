# Piano conversione UserControl in formato VS (Designer + code-behind)

Obiettivo: rendere ogni UserControl compatibile con il designer di Visual Studio, separando in `*.cs` (logica/eventi) e `*.Designer.cs` (InitializeComponent, campi, component container).

## UserControl da convertire (uno per step)
1) ActionButtonsControl
   - Campi: pulsanti Registrati, Conferma email, Login, Conferma MFA, Refresh, Attiva/Disattiva MFA, Mostra profilo, Logout, Mostra QR; checkbox Remember.
   - Layout: posizioni fisse in colonna (circa x=0, y=0..); Size 155x30 per i bottoni.
   - Designer: istanzia i controlli, setta Name/Size/Location/TabIndex, aggiunge Controls.
   - Code-behind: eventi public (RegisterClicked ecc.), metodi SetEnabled/SetMfaEnabled/SetQrEnabled, proprietà RememberChecked.
   - Designer note: `components` container, `SuspendLayout/ResumeLayout`, nessun calcolo; impostare `AutoScaleDimensions/AutoScaleMode` standard.
2) UrlInputControl
   - Campi: label “Base URL:”, textbox URL.
   - Layout: label x=0,y=6; textbox x≈90,y=2,width≈380.
   - Designer: campi + InitializeComponent; code-behind: proprietà UrlText/LabelText.
   - Designer note: TabIndex label=0, textbox=1; Width fisso, Dock None.
3) PasswordInputControl
   - Campi: label “Password:”, textbox password (UseSystemPasswordChar=true).
   - Layout: label x=0,y=6; textbox x≈90,y=2,width≈200.
   - Designer: campi + InitializeComponent; code-behind: proprietà PasswordText/LabelText.
   - Designer note: impostare `UseSystemPasswordChar` nel Designer.
4) StatusInfoControl
   - Campi: badge, stato, utente, sessionId, exp, remember, MFA.
   - Layout: etichette impilate con Location fissa (es. y=0,32,52,...).
   - Designer: campi + InitializeComponent; code-behind: SetStatus, SetMfa, SetRemember.
   - Designer note: Colors impostati in InitializeComponent; nessun Dock Fill.
5) MfaPanelControl
   - Campi: label challenge, textbox challenge, textbox TOTP, bottoni MFA (conferma/attiva/disattiva/QR), PictureBox QR, label stato MFA.
   - Layout: label+textbox in alto, bottoni in colonna, QR a destra, label stato in basso.
   - Designer: campi + InitializeComponent; code-behind: eventi (Confirm/Setup/Disable/ShowQr), proprietà ChallengeId/TotpCode, SetMfaState, SetQrImage, SetButtonsEnabled/SetMfaEnabled/SetQrEnabled.
   - Designer note: impostare Size complessiva, nessun Table/Flow, posizionare QR con Size 160x160.
6) LogPanelControl
   - Campi: label, TextBox output readonly multilinea, ListBox log.
   - Layout: label in alto, output sotto, listbox sotto; posizioni fisse.
   - Designer: campi + InitializeComponent; code-behind: AppendOutput/AddLog, proprietà OutputBox/LogBox.
   - Designer note: output con ScrollBars Vertical, ReadOnly=true; listbox con Height fissa.
7) LabeledTextBoxControl
   - Campi: label generica, textbox.
   - Layout: label x=0,y=6; textbox x≈90,y=2,width≈220.
   - Designer: campi + InitializeComponent; code-behind: proprietà LabelText/ValueText.
   - Designer note: TabIndex label=0, textbox=1; AutoSize label true.
8) StatusBanner (opzionale ma consigliato)
   - Campi: panel, label.
   - Layout: label a tutta larghezza dentro il panel; Dock del banner Top, panel Dock None con size fissa.
   - Designer: campi + InitializeComponent; code-behind: UpdateState.
   - Designer note: impostare `AutoScaleDimensions/Mode`, `Suspend/ResumeLayout`.

## Checklist per ciascun controllo
- Creare file `NomeControl.Designer.cs` con:
  - `partial class NomeControl`
  - `IContainer components = null;`
  - Metodo `InitializeComponent()` che istanzia e posiziona i controlli, setta Name/Size/Location, aggiunge Controls, chiama `ResumeLayout`.
  - Override `Dispose(bool disposing)` che libera `components`.
- Aggiornare `NomeControl.cs`:
  - Dichiarare il costruttore che chiama `InitializeComponent()`.
  - Tenere solo logica/eventi/proprietà pubbliche.
  - Rimuovere inizializzazioni inline spostate nel Designer.
- Verifiche dopo ogni controllo:
  - `dotnet build clients/WinFormsClient/WinFormsClient.csproj`.
  - Apertura nel designer (attesa compatibilità).

## Ordine operativo suggerito
1. ActionButtonsControl
2. UrlInputControl
3. PasswordInputControl
4. LabeledTextBoxControl
5. StatusInfoControl
6. MfaPanelControl
7. LogPanelControl
8. StatusBanner (se si vuole allineare tutto)

## Note
- Usare DockStyle.None, posizioni fisse e dimensioni esplicite come già definite.
- Mantenere nomi dei campi coerenti tra .cs e Designer.
- Dopo conversione di tutti i controlli, build finale e apertura MainForm nel designer.
