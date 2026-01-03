# Piano di azione – id_token leggero interno
Obiettivo: emettere un id_token (JWT) aggiuntivo in login/confirm-mfa per fornire claim di identità al client, senza implementare l’intero OIDC.

## Obiettivi
- Generare un id_token firmato separato dall’access_token, contenente claim identità minimi.
- Chiave di firma separata (RSA consigliato) e parametri dedicati.
- Esposizione opzionale di nonce e amr/acr/auth_time.
- Documentare il consumo per i client (WinForms/postman) e coprire con test.
- Non loggare id_token in chiaro in ambiente non Dev.

## Passi
1) Config/chiavi
   - Aggiungere sezione `IdToken` in appsettings: `Issuer`, `Audience` (o riuso), `SigningKeyPath` (RSA XML/PEM) o generazione on startup; `IncludeEmail` opzionale.
   - Documentare in `appsettings.guida.md`.
   - Preferire chiave RSA dedicata; se non presente, fallback HMAC (meno sicuro, solo dev).
2) Servizio id_token
   - Nuovo `IdTokenService` che crea JWT con:
     - `sub` = userId
     - `aud`, `iss` dai settings
     - `iat`, `auth_time` (UTC now)
     - `amr` (es. ["pwd"], oppure ["pwd","mfa"] se conferma MFA)
     - `nonce` opzionale (se passato dal client)
     - claim opzionali `email`, `preferred_username`
   - Firma RSA (preferibile) o HMAC separato; esporta parametri di validazione per test.
   - Cache delle chiavi per evitare rigenerazioni; metodo `GetValidationParameters()` per test/introspezione.
3) Program.cs (flow)
   - In `/login` e `/login/confirm-mfa`, dopo aver costruito la sessione, generare anche `idToken` con flag amr coerente.
   - Includere `idToken` nel payload JSON della risposta (non in cookie).
   - Evitare di mettere claim sensibili nei JWT (no secret, no token di conferma).
   - Se il client invia `nonce` (opzionale), propagarlo nell’id_token.
4) Test
   - Aggiungere test xUnit che:
     - Validano firma/scadenza/id/aud dell’id_token con il `IdTokenService` (o con la chiave configurata).
     - Controllano `amr` (“pwd” al login senza MFA, “pwd”,“mfa” dopo confirm-mfa).
     - Verificano presenza/assenza di email/username secondo config.
     - Test con `nonce` per verificarne il roundtrip.
     - Test fallback HMAC (dev) se la chiave RSA non è configurata.
     - Test che l’id_token non viene emesso su login fallito o prima della conferma MFA (solo dopo /login/confirm-mfa).
     - Test che l’id_token cambia `amr` e `auth_time` dopo step-up (login → mfa).
     - Test che il token scade secondo la durata impostata (es. custom `IdToken:Minutes` se aggiunto) o segue l’access token.
5) Client/Docs
   - WinForms: loggare/id_token nel pannello output (solo per dev), non memorizzarlo.
   - Documentare in `DESCRIZIONE_SOLUTION.md` l’id_token e come consumarlo (validazione firma/issuer/audience).
   - Postman: aggiungere una risposta campione con id_token e note di validazione (issuer/audience/exp/signature).

## Note
- Non è OIDC completo: niente discovery/JWKS/authorize. È un token identità per client interni.
- Preferire chiave RSA dedicata (`IdToken:SigningKeyPath`), evitare riuso `Jwt:SecretKey`.
