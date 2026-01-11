## Step 1C – Estensione Sessione e Claim

### Obiettivo
Preparare sessioni/JWT a supportare FIDO2 (senza endpoint).

### Azioni
- Estendere `Models/UserSession` e tabella `user_sessions` per includere:
  - `MfaSatisfied` (bool/integer)
  - `AuthTimeUtc` (ISO string)
- Adeguare `SessionRepository` e inserimenti sessione per valorizzare i nuovi campi (default false/null).
- Aggiornare `IdTokenService`/emissione token per poter includere claim `amr`/`auth_time` (anche per FIDO2).

### Output
- Sessioni pronte a marcare l’esito MFA (FIDO2 o TOTP) e a esporre claim `amr/auth_time` quando saranno usati dagli endpoint.
