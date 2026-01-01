# Piano UI stato WinForms (card + badge + banner)

Obiettivo: stato visivo chiaro (non solo testo) per autenticazione/sessione.

## Step 1: Badge stato
- Aggiungere una piccola etichetta/box colorata (rosso/non autenticato, verde/autenticato, arancio/scaduto) con icona/emoticon.
- Aggiornare in `SetState` insieme alle label esistenti.
- Build WinForms.

## Step 2: Card sessione
- Aggiungere un pannello/card che mostra utente, sessionId (troncato), exp e uno sfondo leggero distinto.
- Aggiornare i campi in `SetState`.
- Build WinForms.

## Step 3: Banner superiore
- Aggiungere una barra orizzontale sopra la form con il messaggio sintetico (es. “Non autenticato” / “Loggato come X” / “Sessione scaduta”), con colore di sfondo coerente con lo stato.
- Aggiornare in `SetState`.
- Build WinForms.

Note
- Mantenere i log e gli output testuali; non cambiare logica.
- Colori suggeriti: Rosso scuro (#b22222) per non autenticato, Verde (#2e8b57) per autenticato, Arancio (#d2691e) per scaduto.
