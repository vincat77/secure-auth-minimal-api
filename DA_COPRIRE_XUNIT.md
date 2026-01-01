# Piano copertura xUnit da estendere

Obiettivo: aumentare la copertura automatizzata delle aree non ancora testate, con step piccoli e configurabili.

1) Policy password e configurazione
- Testare combinazioni policy (solo upper, solo digit, upper+digit+symbol) con esiti 400 e messaggi coerenti.
- Testare valori di configurazione incoerenti (es. MinLength mancante o <1) e verificare risposta sicura/fail fast.

2) Log e audit
- Verificare che LoginAudit persista outcome e dettagli strutturati (success/failure/lockout) senza PII sensibili.
- Validare formato log (log category e messaggi chiave) su tentativi login ok/ko e logout.

3) Migrazioni/schema DB
- Test idempotenza di DbInitializer: chiamate multiple non devono fallire né duplicare colonne.
- Test compatibilità con DB preesistente senza nuove colonne (simulare schema vecchio -> ensure).

4) Rate limit/lockout
- Parametrizzare soglie/durate via config e testare: es. lockout dopo 3 tentativi, sblocco dopo durata scaduta.
- (Futuro) Aggiungere throttling per IP e test combinato IP+username.

5) MFA/TOTP
- Test che un utente con TOTP attivo senza codice ottiene 401 con reason mfa_required (già presente parzialmente).
- Aggiungere test per rotazione segreto (se introdotta) e blocco login con codice riusato se implementato.

6) Error handling
- Verificare che gli endpoint restituiscano errori JSON omogenei per input mancante, CSRF errato, token mancante/invalid.
- Testare tampering token (aud/iss) già coperti; aggiungere firma/alg non supportato se si modifica validazione.

7) Configurazione assente/errata
- Test avvio applicazione quando Jwt:SecretKey mancante o troppo corta → fail esplicito.
- Test stringa connessione mancante → errore chiaro.

8) Postman/contract
- Validare che gli endpoint rispondano con shape documentata (campi ok/error) per future collection.

Priorità suggerita: 1) Policy config, 2) Log/Audit, 3) Migrazioni idempotenti, 4) Rate limit parametrico, 5) Error handling uniforme. Ogni step deve aggiungere test + eventuale piccolo adeguamento codice.
