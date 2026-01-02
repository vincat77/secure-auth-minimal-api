# Guida appsettings.json (SecureAuthMinimalApi)
Descrizione di ogni sezione/chiave, utilizzo e valori attesi.

## Jwt
- `Jwt:Issuer` — Issuer del token JWT. Valore stringa; in produzione usare un URL/URN univoco.
- `Jwt:Audience` — Audience attesa dei token. Stringa; deve coincidere con i client che li validano.
- `Jwt:SecretKey` — Chiave simmetrica per firmare i JWT. Min 32 caratteri; mettere in variabile d’ambiente/KeyVault in prod.
- `Jwt:AccessTokenMinutes` — Durata (minuti) del token d’accesso. Intero >0; tipicamente 5–15 in prod.

## LoginThrottle
- `LoginThrottle:MaxFailures` — Tentativi di login falliti prima del lockout. Intero ≥1.
- `LoginThrottle:LockMinutes` — Durata lockout (minuti) dopo superamento soglia. Intero ≥1.

## Cookie
- `Cookie:RequireSecure` — Se true, flag Secure obbligatorio per i cookie. In prod deve restare true.

## ConnectionStrings
- `ConnectionStrings:Sqlite` — Stringa di connessione SQLite. In prod usare percorso sicuro o altro provider.

## PasswordPolicy
- `PasswordPolicy:MinLength` — Lunghezza minima password. Intero ≥1 (consigliato ≥12).
- `PasswordPolicy:RequireUpper` — Richiede almeno una maiuscola. Bool.
- `PasswordPolicy:RequireLower` — Richiede almeno una minuscola. Bool.
- `PasswordPolicy:RequireDigit` — Richiede almeno una cifra. Bool.
- `PasswordPolicy:RequireSymbol` — Richiede almeno un simbolo. Bool.

## UsernamePolicy
- `UsernamePolicy:Lowercase` — Se true, normalizza username in minuscolo per registrazione/login. Bool.

## RememberMe (refresh cookie)
- `RememberMe:Days` — Durata del refresh/remember (giorni). Intero >0.
- `RememberMe:SameSite` — SameSite del cookie refresh (`Strict` o `Lax`). Stringa standard.
- `RememberMe:CookieName` — Nome del cookie refresh. Stringa.
- `RememberMe:Path` — Path del cookie refresh (es. `/refresh`). Stringa.

## Mfa
- `Mfa:ChallengeMinutes` — Validità di un challenge MFA (minuti). Intero >0.
- `Mfa:RequireUaMatch` — Richiede match User-Agent tra login e conferma. Bool.
- `Mfa:RequireIpMatch` — Richiede match IP (o subnet) per la conferma. Bool.
- `Mfa:MaxAttemptsPerChallenge` — Tentativi TOTP per challenge. Intero ≥1.

## Device
- `Device:CookieName` — Nome cookie device-id. Stringa.
- `Device:SameSite` — SameSite del cookie device (`Strict`/`Lax`). Stringa.
- `Device:RequireSecure` — Flag Secure per cookie device. Bool; true in prod.
- `Device:PersistDays` — Durata cookie device (giorni). Intero >0.
- `Device:ClearOnLogoutAll` — Se true, cancella cookie device su logout-all. Bool.

## Session
- `Session:IdleMinutes` — Timeout di inattività sessione (minuti). ≤0 per disabilitare idle timeout.

## Tests
- `Tests:SkipDbInit` — Se true, salta init DB (solo test/dev). Bool.

## Serilog
- `Serilog:Using` — Liste di assembly sink. Array stringhe (es. `Serilog.Sinks.File`, `Serilog.Sinks.Console`).
- `Serilog:MinimumLevel:Default` — Livello minimo generale (Verbose/Debug/Information/Warning/Error/Fatal).
- `Serilog:MinimumLevel:Override` — Override per namespace (es. Microsoft, Microsoft.AspNetCore). Stringhe livello.
- `Serilog:Enrich` — Enrichers (FromLogContext, WithMachineName, ecc.). Array stringhe.
- `Serilog:WriteTo` — Sink configurati:
  - `Name: File` con `Args.path` (es. `logs/log-.txt`), `rollingInterval` (Day), `shared`, `outputTemplate`.
  - `Name: Console` per output console.

## Logging (ASP.NET Core)
- `Logging:LogLevel:Default` — Livello log generico per hosting. (Trace/Debug/Information/Warning/Error/Critical/None).
- `Logging:LogLevel:Microsoft.AspNetCore` — Override per pipeline ASP.NET Core. Stringa livello.
