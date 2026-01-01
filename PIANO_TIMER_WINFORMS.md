# Piano: countdown scadenze in WinFormsClient

Obiettivo: mostrare in WinForms un conto alla rovescia live per scadenza sessione/JWT e altri parametri collegati (exp sessione, eventuale refresh futuro), con timer/aggiornamenti UI.

## Assunzioni
- L’API espone in `/me` `expiresAtUtc` (fine sessione/JWT). Non abbiamo refresh token o altri timer lato client.
- La WinForms usa `CookieContainer` e non legge il JWT; useremo `expiresAtUtc` restituito da `/me`.
- Aggiornamenti UI devono essere thread-safe (InvokeRequired).

## Step tecnici
1) **Dati sessione locali**
   - Estendere `SessionCard` (o nuovo DTO) per conservare `ExpiresAtUtc` come `DateTime?` in UTC.
   - Convertire la stringa ISO di `/me` in `DateTime` e salvarla nello stato corrente.

2) **Timer UI**
   - Aggiungere un `System.Windows.Forms.Timer` (es. tick 1s) in `MainForm` per aggiornare il countdown.
   - On tick: se esiste una `ExpiresAtUtc`, calcolare il delta (UTC) e aggiornare il testo “Scade tra hh:mm:ss”. Se delta <= 0, mostra “Scaduta” e setta stato coerente.
   - Fermare/riavviare il timer quando lo stato cambia (login/logout).

3) **Visualizzazione**
   - Aggiornare `SessionCard` per mostrare: scadenza ISO e countdown live (etichetta dedicata).
   - Opzionale: colorare il countdown in arancione <5 minuti, rosso <1 minuto.
   - **User control**: se possibile, spostare il rendering countdown in un nuovo controllo (es. `SessionCountdownControl`) che riceve `ExpiresAtUtc` e aggiorna il testo/colore; `SessionCard` può ospitarlo.

4) **Gestione scadenza**
   - Se countdown raggiunge 0, disabilitare i pulsanti protetti (me, logout, MFA) e mostrare stato “Sessione scaduta” senza attendere un 401.
   - Pulire il cookie container? (opzionale) Per ora solo stato UI e avviso.

5) **Test manuali rapidi**
   - Login: verificare countdown parte da ~durata token (es. 30 min nei test) e decresce ogni secondo.
   - Logout: countdown si azzera e si ferma.
   - Simulare scadenza: forzare `ExpiresAtUtc` a passato e verificare stato “Scaduta”.

6) **(Opzionale) Timer multipli**
   - Se in futuro aggiungiamo refresh token/lockout/CSRF expiry, prevedere struttura riutilizzabile con una lista di “timer monitorati” (nome + scadenza) da renderizzare nel card.

7) **(Opzionale) Grafico/progress bar**
   - Aggiungere in `SessionCard` una progress bar che mostra la percentuale di vita residua della sessione: 100% al created, 0% all’exp.
   - Calcolo: `(exp - now) / (exp - created)` clamp 0..1; aggiornare al tick del timer.
   - Colorazione: verde >50%, giallo 20–50%, rosso <20%.
