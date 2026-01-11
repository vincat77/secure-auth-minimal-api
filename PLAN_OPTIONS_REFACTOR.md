# Piano refactor Options (SecureAuthMinimalApi)

## Obiettivo
Uniformare la lettura della configurazione passando da `IConfiguration` disperso negli endpoint a `IOptions<T>` (con validazione all’avvio) per ridurre duplicazioni e divergenze tra codice e test.

## Ambito
- Endpoints: login, refresh, logout, change-password/email, MFA setup/confirm, password reset.
- Options: PasswordPolicy, RememberMe, Device, Refresh, Jwt/IdToken, (eventuale) Cookie/Session.
- Test: riallineare l’uso di config nelle suite di integrazione/unit.

## Step proposti

1) Mappatura e inventario (breve)
   - Letture dirette `IConfiguration[...]`:
     * `Endpoints/LoginEndpoints.cs`: legge RememberMe, Device, Refresh cookie (name/path/samesite), password policy, flag cookie.
     * `Endpoints/RefreshEndpoints.cs`: legge Refresh cookie (name/path/samesite/secure/AllowSameSiteNone), RequireUserAgentMatch.
     * `Endpoints/LogoutEndpoints.cs` / `LogoutAllEndpoints.cs`: legge nomi/path cookie refresh/device.
     * `Endpoints/ChangePasswordEndpoints.cs`: `LoadPasswordPolicy` via `IConfiguration.GetValue`.
     * `Endpoints/PasswordResetEndpoints.cs`: mix `PasswordResetConfig` + letture raw di `PasswordPolicy:*`.
     * `Endpoints/MfaSetup/ConfirmMfa`: riuso config cookie/device/refresh post-MFA.
     * `Program.cs`: log/validazione (ok), ma alcuni valori propagati agli endpoint senza options dedicate.
   - Options già esistenti: `PasswordPolicyOptions`, `RememberMeOptions`, `DeviceOptions`, `RefreshOptions`, `PasswordResetConfig`, `CleanupOptions`, `JwtOptions`, `IdTokenOptions`.
   - Gap: `RefreshOptions` non include cookie name/path/samesite/secure; manca una `CookieOptions`/`SessionOptions`; password policy letta raw in alcuni endpoint; reset password mescola config e letture raw.

2) Definizione/estensione options
   - Completare le classi options mancanti o incomplete:
     - `CookieOptions` (RequireSecure, SameSite default, Path?).
     - `SessionOptions` (IdleMinutes, ecc.).
     - Estendere `RefreshOptions` per includere cookie name/path/SameSite/AllowSameSiteNone/RequireSecure (oggi letti raw).
     - Verificare se `DeviceOptions` e `RememberMeOptions` coprono tutti i campi usati nei cookie.
   - Aggiungere `ValidateDataAnnotations`/validator custom per default coerenti.

3) Bind e validazione in Program.cs
   - Registrare tutte le options con `builder.Services.Configure<...>(...)` e `ValidateOnStart`.
   - Rimuovere letture dirette di `IConfiguration` negli endpoint sostituendole con options iniettate via DI.

4) Refactor endpoint
   - Login/LoginMfa/ConfirmMfa: usare `IOptions<RememberMeOptions>`, `IOptions<DeviceOptions>`, `IOptions<RefreshOptions>`, `IOptions<PasswordPolicyOptions>`.
   - Refresh: usare `IOptions<RefreshOptions>` (UA match, cookie name/path/samesite/secure).
   - Logout/LogoutAll: usare `RefreshOptions`/`SessionOptions` per nomi cookie, ecc.
   - ChangePassword/ChangeEmail: usare `PasswordPolicyOptions`, `EmailConfirmation`, ecc.
   - PasswordReset: già usa `PasswordResetConfig`; verificare coerenza con EmailConfirmation.

5) Test aggiornati
   - Aggiornare i test che leggono config raw (`IConfiguration`) per usare `IOptions<...>` o helper.
   - Assicurarsi che i factory di test impostino le section config per le options nuove.

6) Documentazione
   - Aggiornare `appsettings.guida.md` con le nuove sezioni/chiavi (Cookie/Session/Refresh esteso).

## Output atteso
- Nessuna lettura diretta di `IConfiguration[...]` negli endpoint; solo options iniettate.
- Validazione config all’avvio (fail-fast per valori invalidi).
- Test verdi con config coerente a options.

## Note
- Procedere per batch (es. refresh/logout, poi login/MFA, poi change-password/email).
- Mantenere piccoli commit per ridurre rischi di regressione.
