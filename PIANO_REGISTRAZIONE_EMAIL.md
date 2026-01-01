# Piano: conferma email e normalizzazione username/email

Obiettivo: rafforzare la registrazione con conferma email (token a tempo) e normalizzazione case-insensitive.

## Passi tecnici
1) Schema DB (piccolo passo)
   - Aggiungere colonne a `users`: `email`, `email_normalized`, `email_confirmed` (bool), `email_confirm_token`, `email_confirm_expires_utc`.
   - Migrazione compatibile con schema esistente (alter/add column).

2) Input e normalizzazione (piccolo passo)
   - Aggiornare DTO di registrazione per accettare `Email`.
   - Normalizzare email/username in lower/invariant.
   - Lookup user/email case-insensitive usando le colonne normalizzate.

3) Generazione token in /register (piccolo passo)
   - In `POST /register` creare token conferma (GUID), scadenza (es. +24h), settare `email_confirmed=false`.
   - Restituire in risposta il token (solo per dev/test) o loggarlo.

4) Endpoint di conferma (piccolo passo)
   - Aggiungere `POST /confirm-email` che accetta token, verifica scadenza e marca `email_confirmed=true`.
   - Gestire token scaduto/invalid (400/410).

5) Blocco login se non confermato (piccolo passo)
   - In login, se utente non demo e `email_confirmed=false`, rispondere 403 con reason `email_not_confirmed`.

6) Test xUnit (passo dedicato)
   - Register -> conferma -> login OK.
   - Register -> login prima di conferma -> 403 `email_not_confirmed`.
   - Token scaduto -> 410 (o 400) su confirm.
   - Case-insensitive email/username.

7) WinForms (opzionale, dopo)
   - Aggiungere campo Email e simulare conferma via endpoint (in dev).

Note
- Invio email reale non incluso: in dev il token si ottiene dalla risposta/log. In prod andrà sostituito con SMTP/servizio email.
- Omografi e blocklist domini fuori scope per ora.
