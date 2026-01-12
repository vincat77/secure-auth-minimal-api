## Step 1A – Opzioni e Servizio FIDO2

### Obiettivo
Preparare opzioni/config e servizio FIDO2 (senza toccare DB o endpoint).

### Azioni
- Creare `Options/FidoOptions.cs` con campi tipizzati:
  - `string RpId`
  - `string Origin`
  - `string RpName`
  - `int ChallengeTtlMinutes = 5`
- Binding in `Program.cs` (`AddOptions<FidoOptions>().Bind(...)`), validazione campi non vuoti.
  - Esempio (coerente con gli altri options):
    ```csharp
    builder.Services.AddOptions<FidoOptions>()
        .Bind(builder.Configuration.GetSection("Fido"))
        .Validate(options =>
            !string.IsNullOrWhiteSpace(options.RpId) &&
            !string.IsNullOrWhiteSpace(options.Origin) &&
            !string.IsNullOrWhiteSpace(options.RpName) &&
            options.ChallengeTtlMinutes > 0,
            "Fido options invalid: RpId/Origin/RpName obbligatori, TTL > 0");
    ```
- Documentare sezione `Fido` in `appsettings.guida.md`, con esempio:
  ```json
  "Fido": {
    "RpId": "example.com",
    "Origin": "https://example.com",
    "RpName": "SecureAuthMinimalApi",
    "ChallengeTtlMinutes": 5
  }
  ```
  Significato:
  - `RpId`: dominio del relying party usato da WebAuthn (deve combaciare con l’host delle richieste).
  - `Origin`: origin completo (schema+host+porta) accettato in WebAuthn; deve essere HTTPS in prod.
  - `RpName`: nome descrittivo mostrato al client WebAuthn.
  - `ChallengeTtlMinutes`: TTL massimo per le challenge generate (min > 0).
- Creare `Services/Fido2Service.cs` che incapsula `Fido2-Net-Lib` per:
  - `GenerateRegistrationOptions(sessionId, userId, username/displayName)`: crea challenge random, lega a sessionId, TTL da config; restituisce PublicKeyCredentialCreationOptions senza loggare challenge.
  - `VerifyAttestation(options, attestationResponse)`: verifica origin/rpId, ritorna `FidoCredential` (credentialId/publicKey/aaguid/signCount) pronto per il salvataggio; non salva nulla e non logga raw attestation.
  - `GenerateAssertionOptions(credentialIds)`: crea challenge per auth (legata a sessionId con TTL), filtra credenziali dell’utente; no log challenge.
  - `VerifyAssertion(options, assertionResponse, storedCredential)`: verifica origin/rpId, controlla e incrementa signCount (rifiuta decrementi), restituisce signCount aggiornato; mai loggare credentialId/raw response.
- Documentare sezione `Fido` in `appsettings.guida.md` (RpId, Origin, RpName, ChallengeTtlMinutes).

### Output
- Opzioni FIDO2 registrate e validate.
- Servizio pronto a essere usato dagli endpoint.

### Test (xUnit) da implementare
- Positivi:
  - `FidoOptions_binding_valid_config`: bind OK con RpId/Origin/RpName/TTL > 0 → nessuna eccezione, valori attesi.
  - `Fido2Service_generates_challenge_with_ttl`: la challenge ha TTL ≤ configurato e non è null → Assert.NotNull(challenge), expTime <= now+TTL.
- Negativi:
  - `FidoOptions_binding_requires_rpid_and_origin`: avvio con config mancante deve fallire/avvisare → Assert.Throws/errore di validazione.
  - `Fido2Service_validate_attestation_rejects_wrong_origin`: attestation con origin errata → Assert.Throws o risultato non valido.
  - `Fido2Service_validate_assertion_rejects_wrong_rpid`: assertion con rpId errato → Assert.Throws o risultato non valido.
  - `Fido2Service_does_not_log_sensitive_data`: logger fake non deve contenere challenge/credentialId/raw attestation → Assert.DoesNotContain su log.

### Supporto test
- Riutilizzare `WebApplicationFactory<Program>` per bind/config in-memory (pattern già usato nei test esistenti).
- Logger fake/in-memory per ispezionare messaggi (`ILoggerProvider` custom).
- Stub/mock `IFido2` o helper Fido2-Net-Lib per creare attestation/assertion minime senza parlare con browser.
- Helper config in-memory (`Dictionary<string,string?>`) come negli altri test.

### Note operative aggiuntive
- Pacchetto da aggiungere: `Fido2-Net-Lib` (versione stabile corrente) e, se necessario, un wrapper `IFido2` per DI.
- Storage challenge: decidere se usare cache in-memory con TTL o tabella `fido_challenges` con campi `session_id`, `challenge`, `expires_at_utc`. Deve essere legata alla sessione.
- Ambienti: prevedere valori `Fido` diversi per Dev/Staging/Prod (RpId/Origin specifici), binding per ambiente come già fatto per altre sezioni.
- Validazione: usare `ValidateOnStart` → in caso di config mancante aspettarsi `OptionsValidationException` all’avvio.
- Complessità: step a bassa complessità, indipendente dagli endpoint ma propedeutico ai passi 1B/1C/2/3.
