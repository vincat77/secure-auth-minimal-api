## Step 1A – Opzioni e Servizio FIDO2

### Obiettivo
Preparare opzioni/config e servizio FIDO2 (senza toccare DB o endpoint).

### Azioni
- Creare `Options/FidoOptions.cs` con: `RpId`, `Origin`, `RpName`, `ChallengeTtlMinutes=5`.
- Binding in `Program.cs` (`AddOptions<FidoOptions>().Bind(...)`), validazione campi non vuoti.
- Creare `Services/Fido2Service.cs` che incapsula `Fido2-Net-Lib` per:
  - generare challenge (con TTL)
  - validare attestation/assertion (origin/rpId)
  - mai loggare challenge/attestation/raw
- Documentare sezione `Fido` in `appsettings.guida.md` (RpId, Origin, RpName, ChallengeTtlMinutes).

### Output
- Opzioni FIDO2 registrate e validate.
- Servizio pronto a essere usato dagli endpoint.
