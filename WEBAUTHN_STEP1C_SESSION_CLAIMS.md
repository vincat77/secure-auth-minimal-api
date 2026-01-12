## Step 1C – Estensione Sessione e Claim

### Obiettivo
Preparare sessioni/JWT a supportare FIDO2 (senza endpoint).

### Azioni
- Estendere `Models/UserSession` e tabella `user_sessions` per includere:
  - `MfaSatisfied` (bool/integer)
  - `AuthTimeUtc` (ISO string)
- Adeguare `SessionRepository` e inserimenti sessione per valorizzare i nuovi campi (default false/null).
- Aggiornare `IdTokenService`/emissione token per poter includere claim `amr`/`auth_time` (anche per FIDO2).
- Aggiungere helper/util per impostare `amr` coerente:
  - Solo password: `["pwd"]`
  - Password + FIDO2: `["pwd","fido2"]`
  - Password + TOTP: `["pwd","otp"]`
- Allineare middleware/jwt auth se validano `amr`/`auth_time` (oggi non usato: aggiungere campi senza breaking change).

### Output
- Sessioni pronte a marcare l’esito MFA (FIDO2 o TOTP) e a esporre claim `amr/auth_time` quando saranno usati dagli endpoint.

### Test (xUnit) da implementare
- `SessionRepository_inserts_mfa_flags_default_false`: nuova sessione ha MfaSatisfied=false, AuthTimeUtc=null.
- `SessionRepository_updates_auth_time_and_flag`: dopo step-up (simulato), i campi vengono aggiornati e letti correttamente.
- `IdTokenService_sets_amr_and_auth_time`: emissione token con diversi scenari (pwd, pwd+fido2, pwd+otp) → claim `amr` coerenti e `auth_time` presente quando MFA soddisfatta.

### Retrocompatibilità
- Considerare migrazione dei record sessione esistenti: nuovi campi `MfaSatisfied`/`AuthTimeUtc` devono avere default sicuri (false/null).
- I token già emessi senza `amr/auth_time` rimangono validi: i nuovi claim sono aggiuntivi e opzionali.
