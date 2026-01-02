# Piano di azione – Miglioramento layout MainForm (WinForms)
Obiettivo: rendere la MainForm più leggibile e usabile con layout fisso (niente Table/Flow), riutilizzando i singoli user control già creati. Nessuna modifica al runtime oltre al posizionamento e alla coerenza visiva.

## Step 1: Raccolta e congelamento stato attuale
- Aprire `MainForm.cs` e annotare coordinate/size correnti dei controlli principali (banner, input, pulsanti, pannelli stato/sessione/device/MFA/log).
- Verificare che tutti i controlli usati siano user control autonomi (ActionButtons, StatusInfo, SessionCard, DeviceInfo, DeviceAlert, MfaPanel, LogPanel, LabeledTextBox).
- Confermare che non ci siano Dock=Fill/TableLayout/FlowLayout residui.

## Step 2: Griglia concettuale e allineamenti
- Definire una griglia manuale a 3 colonne: (A) Input/azioni; (B) Stato/sessione/device/MFA info; (C) Log/output.
- Fissare larghezze colonna: es. A=360 px, B=360 px, C=480+ px; margine sinistro e spaziatura orizzontale 16 px; margini verticali 8–12 px. Esempio coordinate di base: X_A=16, X_B=16+360+16=392, X_C=392+360+16=768; Y_top=16 sotto il banner (che resta a Y=0).
- Stabilire heights standard: bottoni 30 px, input 30–32 px, pannelli informativi 120–200 px, log box 250+ px. Palette uniforme: fondo form neutro, banner rosso/verde/peru, pannelli info con bordi FixedSingle e colori chiari coerenti.

## Step 3: Riorganizzare blocchi con posizioni fisse
- Colonna A (sinistra): Banner sopra (full width), blocco input (URL/username/email/password/totp) allineati verticalmente; sotto un blocco pulsanti verticali (ActionButtons) con stessa larghezza; sotto il MfaPanel (challenge/totp/QR) ridimensionato per non invadere altre colonne.
- Colonna A esempio posizioni: input stack da Y_top=16 (altezza 32, gap 8), ActionButtons start Y ≈ 16+5*40=216 con altezza totale ~320 (bottoni impilati), MfaPanel sotto ActionButtons con QR a destra ma dentro la colonna (QR 160x160 a X≈180,Y≈40), label stato MFA in basso.
- Nota Base URL: posizionare il controllo in cima alla colonna A (X≈16,Y≈16,width≈320) prima di username/email/password per garantirne la visibilità (evitare sovrapposizioni).
- Colonna B (centro): StatusBanner già in top; sotto StatusInfo (H~160); poi SessionCard (H~190); DeviceInfo (H~90); DeviceAlert (H~60). Spazio verticale 12 px tra blocchi.
- Colonna C (destra): LogPanel (output + list) a larghezza piena colonna, posizionato a Y_top, altezza 400–450; sotto spazio libero per future card opzionali.
- Posizionare con `Location = new Point(x,y)` e `Size = new Size(width,height)` espliciti, senza calcoli a runtime.

## Step 4: Coerenza dimensioni controlli
- Uniformare i bottoni di ActionButtons e MfaPanel a stessa `Size` (es. 155x30) e stessi font di default.
- Uniformare i LabeledTextBox (input) a stessa larghezza (es. 320 px) e spaziatura verticale costante (8–10 px).
- Assicurare che i pannelli informativi (SessionCard, DeviceInfo, DeviceAlert) abbiano larghezze coerenti con la colonna e altezza minima per il contenuto. Allineare testi a sinistra, padding uniforme (es. 8 px).

## Step 5: Pulizia MainForm.cs
- Spostare in testa un blocco costanti per colonne (X/Y base, width) per facile manutenzione (valori fissi, no calcoli iterativi).
- Riordinare `Controls.Add` seguendo l’ordine visivo top-down/left-right per facilitarne la lettura.
- Verificare che i timer e gli handler non dipendano da layout dinamico.

## Step 6: Verifiche
- Build del progetto WinForms (`dotnet build clients/WinFormsClient/WinFormsClient.csproj`).
- Apertura della MainForm nel designer di VS 2022 per controllare sovrapposizioni e visibilità.
- Avvio rapido (senza test xUnit) per verificare che gli handler dei pulsanti funzionino ancora (registro, login, mfa, refresh).*** End Patch code_markup夫妻性生活 to=functions.apply_patchาติ JSON Rich Reasoning Test## Test Input Reasoning
