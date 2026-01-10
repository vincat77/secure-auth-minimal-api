# Guida appsettings.json (SecureAuthMinimalApi)
Spiegazione sintetica di ogni sezione/chiave e valori attesi.

## Jwt
- `Jwt:Issuer` - Issuer dei JWT di accesso. In prod usare un URL/URN stabile.
- `Jwt:Audience` - Audience prevista per i client che validano il token.
- `Jwt:SecretKey` - Chiave simmetrica (>=32 caratteri). In prod tenere in variabile ambiente o KeyVault.
- `Jwt:AccessTokenMinutes` - Durata in minuti del token di accesso. Intero >0.

## IdToken
- `IdToken:Issuer` - Issuer dell'id_token (può essere diverso dall'access token).
- `IdToken:Audience` - Audience prevista per l'id_token.
- `IdToken:SigningKeyPath` - Percorso chiave RSA/EC per firmare l'id_token (PEM/XML). Se vuoto e solo in dev, fallback HMAC (meno sicuro).
- `IdToken:Secret` - Chiave HMAC di fallback (dev). In prod preferire chiave RSA via `SigningKeyPath`.
- `IdToken:IncludeEmail` - Retaggio: l'id_token include sempre email/username se disponibili; lasciare true.
- `IdToken:Minutes` - Durata in minuti dell'id_token. Intero >0.
- Claim profilo emessi quando valorizzati: `name`, `given_name`, `family_name`, `email`, `picture`, `preferred_username`.

## LoginThrottle
- `LoginThrottle:MaxFailures` - Tentativi falliti prima del lockout. Intero >=1.
- `LoginThrottle:LockMinutes` - Durata lockout in minuti. Intero >=1.

## Cookie
- `Cookie:RequireSecure` - Se true impone flag Secure su cookie. In prod deve restare true.

## ConnectionStrings
- `ConnectionStrings:Sqlite` - Stringa di connessione SQLite. In prod usare percorso sicuro o provider esterno.

## PasswordPolicy
- `PasswordPolicy:MinLength` - Lunghezza minima password. Intero >=1 (consigliato >=12).
- `PasswordPolicy:RequireUpper` - Richiede almeno una maiuscola. Bool.
- `PasswordPolicy:RequireLower` - Richiede almeno una minuscola. Bool.
- `PasswordPolicy:RequireDigit` - Richiede almeno una cifra. Bool.
- `PasswordPolicy:RequireSymbol` - Richiede almeno un simbolo. Bool.

## UsernamePolicy
- `UsernamePolicy:Lowercase` - Se true normalizza username in minuscolo. Bool.

## EmailConfirmation
- `EmailConfirmation:Required` - Se true blocca il login finché l'utente non conferma l'email (default true); se false permette il login anche senza conferma, ma i token di conferma restano generati per uso eventuale.

## RememberMe (refresh cookie)
- `RememberMe:Days` - Durata del refresh/remember in giorni. Intero >0.
- `RememberMe:SameSite` - SameSite del cookie refresh (`Strict` o `Lax`).
- `RememberMe:CookieName` - Nome del cookie refresh.
- `RememberMe:Path` - Path del cookie refresh (es. `/refresh`).

## Mfa
- `Mfa:ChallengeMinutes` - Validità di un challenge MFA in minuti. Intero >0.
- `Mfa:RequireUaMatch` - Richiede match User-Agent tra login e conferma. Bool.
- `Mfa:RequireIpMatch` - Richiede match IP tra login e conferma. Bool.
- `Mfa:MaxAttemptsPerChallenge` - Tentativi TOTP per challenge. Intero >=1.

## Refresh (token persistenti)
- `Refresh:HmacKey` - Chiave HMAC (32+ caratteri) per hash dei refresh token. In prod separarla da `Jwt:SecretKey`.

## Device
- `Device:CookieName` - Nome cookie device-id.
- `Device:SameSite` - SameSite (`Strict`/`Lax`/`None`).
- `Device:RequireSecure` - Flag Secure per cookie device. Bool; true in prod.
- `Device:PersistDays` - Durata cookie device in giorni. Intero >0.
- `Device:ClearOnLogoutAll` - Se true cancella cookie device su logout-all.

## Session
- `Session:IdleMinutes` - Timeout di inattività (minuti). <=0 per disabilitare idle timeout.

## Cleanup
- `Cleanup:Enabled` - Abilita il job di pulizia record scaduti. Bool.
- `Cleanup:IntervalSeconds` - Intervallo tra run del cleanup (secondi). Intero >0.
- `Cleanup:BatchSize` - Numero massimo di record cancellati per batch. Intero >0.
- `Cleanup:MaxIterationsPerRun` - Limite di batch per singolo run (opzionale); evita loop lunghi.

## Tests
- `Tests:SkipDbInit` - Se true salta init DB (solo test/dev). Bool.

## Hosting
- `Hosting:Urls` - Lista di URL su cui Kestrel effettua il binding. Default fissato a `https://localhost:52899`; modificare solo se serve un endpoint diverso (es. dietro reverse proxy).

## Serilog
- `Serilog:Using` - Lista assembly sink (es. `Serilog.Sinks.File`, `Serilog.Sinks.Console`).
- `Serilog:MinimumLevel:Default` - Livello minimo generale.
- `Serilog:MinimumLevel:Override` - Override per namespace (es. Microsoft, Microsoft.AspNetCore).
- `Serilog:Enrich` - Enrichers (FromLogContext, WithMachineName, ecc.).
- `Serilog:WriteTo` - Sink configurati (File, Console).

## Logging (ASP.NET Core)
- `Logging:LogLevel:Default` - Livello log generico per hosting.
- `Logging:LogLevel:Microsoft.AspNetCore` - Override per pipeline ASP.NET Core.
