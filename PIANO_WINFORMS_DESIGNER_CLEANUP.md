# Piano WinForms Designer Cleanup

Obiettivo: rendere `MainForm` compatibile con il designer di Visual Studio eliminando TableLayoutPanel/FlowLayoutPanel, usando solo Panel e UserControl, con layout esplicito e file designer pulito.

## Passi proposti

1) **Inventario controlli**
   - Elencare controlli in `MainForm.Designer.cs`: UrlInputControl, PasswordInputControl, user/email/totp text box, pulsanti (login/registrazione/MFA/logout/refresh/QR), checkbox remember, challenge box, QR picture box, output log, conferma email token, badge/stato, session card, device info/alert, banner.
   - Verificare UserControl esistenti: UrlInputControl, PasswordInputControl, SessionCard, DeviceInfoControl, DeviceAlertControl, SessionCountdownControl, RefreshCountdownControl.
   - Individuare controlli da raggruppare in eventuali nuovi UserControl (stato utente, challenge/QR).

2) **Ripulire MainForm.cs**
   - Eliminare campi readonly duplicati (textbox, label, button) in favore dei campi generati dal designer.
   - Rimuovere ogni uso di TableLayoutPanel/FlowLayoutPanel nel costruttore; il costruttore deve solo chiamare `InitializeComponent` e agganciare gli handler.
   - Nessun DockStyle.Fill: tutti i controlli del designer devono avere DockStyle.None e coordinate esplicite.
   - Mantenere solo logica/business (HTTP, eventi) in `MainForm.cs` usando i controlli del designer (UrlInputControl/PasswordInputControl ecc.).

3) **Rigenerare MainForm.Designer.cs**
   - Sostituire il layout attuale con:
     - Pannello sinistro per campi e pulsanti, posizionati con Location/Size espliciti (es. x=10, larghezza input 300–500).
     - Pannello destro per stato/sessione/device/alert (posizioni fisse, es. x=550, larghezza 320–350).
     - `AutoScroll` abilitato se serve.
   - Nessun calcolo o loop: tutte le coordinate hardcoded.
   - Usare gli UserControl esistenti per URL e password; valutare UserControl per blocchi stato/sessione se utile.
   - Assicurare Name/TabIndex coerenti; ancoraggi solo Left/Top o Left/Top/Right se serve allargamento orizzontale.
   - Esempio di schema (indicativo, da affinare in designer):
     - Colonna sinistra (x≈10):
       - URL control y=10 width≈500
       - Username y=50 width≈300
       - Email y=80 width≈300
       - Password control y=110 width≈320
       - TOTP y=145 width≈300
       - Pulsanti (ActionButtons control) y=180 width≈180 height a colonna
       - Challenge/MFA control y=330 (challenge textbox + bottoni + QR, width≈500)
       - LogPanel y=520 (output log + list log, width≈700)
       - Token conferma email y=700 width≈300
     - Colonna destra (x≈550):
       - Stato/Badge control y=20 width≈320
       - SessionCard y=80 width≈320
       - DeviceInfo control y=220 width≈320
       - DeviceAlert control y=320 width≈320
   - Impostare `AutoScroll = true` sul form e sui pannelli lunghi (sinistra/destra) per evitare contenuti nascosti.

4) **UserControl aggiuntivi (step operativi)**
   - Step 4.1: ActionButtons Control (colonna verticale)
     - Campi: Registrati, Conferma email, Login (password), Refresh, Logout, Mostra profilo, Mostra QR MFA, checkbox Remember.
     - Eventi click esposti; proprietà Enabled di gruppo.
     - Posizionamento interno: bottoni uno sotto l’altro con Size uniforme (es. 155x30), Location fissa (no layout manager).
     - Esporre proprietà per testo pulsanti se serve localizzazione.
   - Step 4.2: Stato/Badge Control (piccolo, no layout manager)
     - Campi: badge (colori stato), stato, utente, sessionId, scadenza, remember.
     - Metodo `SetState(userId, sessionId, exp, remember, badgeText, badgeColor)`.
     - Posizionamento interno: etichette impilate verticalmente con Location fissa; colore badge impostabile.
   - Step 4.3: LogPanel Control
     - Campi: label “Log eventi”, TextBox multilinea readonly, ListBox log eventi.
     - Proprietà MaxItems; metodi Append/LogEvent opzionali.
     - Posizionamento interno: label in alto, sotto TextBox (es. height 150), sotto ListBox (es. height 140), con AutoScroll disabilitato.
   - Step 4.4: MFA/Challenge Control
     - Campi: textbox challengeId, bottoni (Conferma MFA, Attiva MFA, Disattiva MFA, Mostra QR), PictureBox QR, label stato MFA.
     - Eventi click esposti; proprietà per challengeId/QR; metodo `SetMfaState(text)`.
     - Posizionamento interno: challenge textbox a sinistra, bottoni in colonna, PictureBox QR dedicato; nessun calcolo runtime.
   - (Esistenti) URL e Password:
     - UrlInputControl, PasswordInputControl già presenti: riutilizzarli nel designer.

5) **Aggiornare references**
   - Assicurarsi che `MainForm.cs` usi i nuovi campi del designer (no campi readonly duplicati).
   - Rimuovere eventuali riferimenti a controlli eliminati/vecchi layout.
   - Aggiornare namespace `using WinFormsClient.Controls;` se si aggiungono nuovi UserControl.
   - Allineare i nomi dei controlli tra designer e code-behind per evitare campi orfani (es. `_urlControl`, `_passwordControl`, `_outputBox`, ecc.).

6) **Verifiche (dopo ogni blocco)**
   - Dopo ogni user control creato/sostituito:
     - `dotnet build clients/WinFormsClient/WinFormsClient.csproj`.
     - Apertura designer in VS (verifica che si apra senza errori).
     - Controllo visivo rapido che i controlli non siano nascosti o sovrapposti.
   - A fine step:
     - `rg "TableLayoutPanel|FlowLayoutPanel|DockStyle.Fill"` per assicurare assenza di layout manager e Dock fill.
     - Verifica EventHandler in `MainForm.cs` puntino ai controlli corretti.
   - Se si aggiungono nuovi user control: build + apertura designer del singolo control.

7) **Pulizia finale**
   - Controllare che non ci siano più FlowLayoutPanel/TableLayoutPanel in WinFormsClient.
   - Confermare assenza di `DockStyle.Fill` sui controlli.
   - Rimuovere eventuali risorse/layout non usati dal .resx se orfani.
   - Ripassare `MainForm.resx` se necessario (salvataggio designer) per eliminare riferimenti a controlli rimossi.

## Note
- Uso esclusivo di Panel + Location/Size, niente calcoli runtime.
- Mantenere eventuali controlli custom già creati; aggiungerne solo se semplificano il designer.
- Priorità: compatibilità designer VS > layout reattivo; privilegiare semplicità e chiarezza delle coordinate.
