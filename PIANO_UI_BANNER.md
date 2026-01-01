# Piano: estrarre Banner di stato in un UserControl

Obiettivo: incapsulare il banner superiore (colore + testo stato) in un controllo riutilizzabile, con API di aggiornamento semplice.

Step
1) Creare `Controls/StatusBanner.cs`
   - Derivato da `UserControl`.
   - Include un Panel/Label interni.
   - Metodo `UpdateState(string state, string? userId)` che imposta testo e colore (verde autent., arancio scaduto, rosso non autenticato).

2) Integrare in `MainForm`
   - Rimuovere `_bannerPanel`/`_bannerLabel` dalla form.
   - Aggiungere campo `StatusBanner _banner`.
   - Aggiungere il controllo al form (DockTop).
   - In `SetState` chiamare `_banner.UpdateState(state, userId)`.

3) Build/Verifica
   - `dotnet build clients/WinFormsClient/WinFormsClient.csproj`.
   - Controllare che non si sovrapponga ai controlli (DockTop) e che colori/testo cambino con `SetState`.
