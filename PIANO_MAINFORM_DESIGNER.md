# Piano di azione – Split MainForm in Designer + Code-behind
Obiettivo: rendere `MainForm` compatibile con il designer di Visual Studio, separando layout (InitializeComponent) da logica. Nessuna modifica funzionale, solo struttura.

## Step 1: Preparazione struttura
- Creare `MainForm.Designer.cs` (partial) nello stesso namespace `WinFormsClient`, con `components`, `Dispose(bool disposing)` e `InitializeComponent()`.
- Spostare nel Designer: istanziazione controlli UI, proprietà grafiche (Text, Name, Size, Location, Padding, BorderStyle, BackColor), `Controls.Add`, `AutoScaleDimensions/Mode`, `ClientSize`, `SuspendLayout/ResumeLayout/PerformLayout`.
- Tenere in `MainForm.cs`: logica HTTP, handler, metodi async (Register/Login/MFA/Refresh/Logout), wiring degli eventi dopo `InitializeComponent()`.

## Step 2: Campi, costanti e naming
- Campi da dichiarare in Designer: `_banner`, `_rootPanel` (AutoScroll), `_urlControl`, `_userInput`, `_emailInput`, `_passwordControl`, `_actions`, `_mfaPanel`, `_confirmTokenInput`, `_statusInfo`, `_sessionCard`, `_deviceInfo`, `_deviceAlert`, `_busyLabel`, `_logPanel`, `_countdownTimer`.
- Usare costanti di layout in Designer (o inline): `ColSpacing=16`, `ColAWidth=360`, `ColBWidth=360`, `ColCWidth=520`, `ColAX=16`, `ColBX=392`, `ColCX=768`, `YTop=16`; `ClientSize=1320x900`.
- Assegnare `Name` a tutti i controlli; impostare `TabIndex` coerenti (input sequenziali, poi pulsanti, poi pannelli).
- Timer in Designer: `new System.Windows.Forms.Timer(components) { Interval = 1000 };` (handlers nel code-behind).

## Step 3: Layout in InitializeComponent
- Creare `_rootPanel` con `AutoScroll=true`, `Size=1280x840`, `Anchor=Top|Left|Right|Bottom`, aggiungerlo al Form dopo il `_banner` (banner Dock=Top).
- Colonna A (X=ColAX): Base URL, Username, Email, Password (Size ~330x30, gap 40 px), ActionButtons (180x380), MfaPanel (380x260), ConfirmTokenInput (330x30). Posizioni come attuali (YTop progressivo).
- Colonna B (X=ColBX): StatusInfo (340x160), SessionCard (340x190), DeviceInfo (340x90), DeviceAlert (340x60), BusyLabel sotto DeviceAlert.
- Colonna C (X=ColCX): LogPanel (ColCWidth x 500) a YTop.
- Usare `SuspendLayout/ResumeLayout` su Form e `_rootPanel` per evitare glitch designer.

## Step 4: Code-behind (MainForm.cs) dopo il refactor
- Costruttore: chiamare `InitializeComponent();` poi impostare valori di default se non già nel Designer (es. ValueText di input), inizializzare HttpClient/handler/cookies, variabili runtime.
- Wiring eventi dopo `InitializeComponent()`: `_actions.RegisterClicked += ...`, `_actions.LoginClicked += ...`, `_mfaPanel.ConfirmMfaClicked += ...`, `_countdownTimer.Tick += ...`, ecc.
- Rimuovere da `MainForm.cs` istanziazioni/Controls.Add/Location/Size (devono stare nel Designer). Mantenere solo logica e metodi.

## Step 5: Verifiche
- `dotnet build clients/WinFormsClient/WinFormsClient.csproj`.
- Aprire `MainForm` nel designer VS 2022: nessun errore di naming; controlli visibili nelle posizioni attese.
- Smoke manuale: avvio client, prova rapido di pulsanti (register/login/logout/MFA) per confermare wiring eventi.

## Note
- Nessuna logica o handler in Designer; solo layout e proprietà statiche.
- Mantenere `AutoScroll` sul panel root per vedere i controlli in basso.
- Se il designer segnala riferimenti mancanti, verificare corrispondenza esatta dei campi tra Designer e code-behind (stessi nomi). 
