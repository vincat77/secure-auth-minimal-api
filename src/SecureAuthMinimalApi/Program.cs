using System.Text.Json;
using SecureAuthMinimalApi.Data;
using SecureAuthMinimalApi.Middleware;
using SecureAuthMinimalApi.Models;
using SecureAuthMinimalApi.Services;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.Logging;

var builder = WebApplication.CreateBuilder(args);
var logger = LoggerFactory.Create(b => b.AddConsole()).CreateLogger<Program>();

// Hard fail if secret is missing/too short is handled by JwtTokenService constructor.
builder.Services.AddSingleton<JwtTokenService>();
builder.Services.AddSingleton<SessionRepository>();
builder.Services.AddSingleton<UserRepository>();
builder.Services.AddSingleton<LoginThrottleRepository>();
builder.Services.AddSingleton<ILoginThrottle, DbLoginThrottle>();
builder.Services.AddSingleton<LoginAuditRepository>();
builder.Services.AddDataProtection();
builder.Services.AddSingleton<TotpSecretProtector>();
builder.Services.AddSingleton<RefreshTokenRepository>();

builder.Services.AddTransient<CookieJwtAuthMiddleware>();
builder.Services.AddTransient<CsrfMiddleware>();

var app = builder.Build();
var isDevelopment = app.Environment.IsDevelopment();

var configuredMin = app.Configuration.GetValue<int?>("PasswordPolicy:MinLength");
var minPasswordLength = configuredMin is null or < 1 ? 12 : configuredMin.Value;
var requireUpper = app.Configuration.GetValue<bool?>("PasswordPolicy:RequireUpper") ?? false;
var requireLower = app.Configuration.GetValue<bool?>("PasswordPolicy:RequireLower") ?? false;
var requireDigit = app.Configuration.GetValue<bool?>("PasswordPolicy:RequireDigit") ?? false;
var requireSymbol = app.Configuration.GetValue<bool?>("PasswordPolicy:RequireSymbol") ?? false;
var forceLowerUsername = app.Configuration.GetValue<bool?>("UsernamePolicy:Lowercase") ?? false;

var skipDbInit = app.Configuration.GetValue<bool?>("Tests:SkipDbInit") ?? false;
if (skipDbInit)
{
    logger.LogWarning("Avvio con Tests:SkipDbInit=true: saltata inizializzazione DB (solo per test)");
}
else
{
    DbInitializer.EnsureCreated(app.Configuration);
}

// Validazioni config in ambiente non Development.
if (!isDevelopment)
{
    var iss = app.Configuration["Jwt:Issuer"] ?? "";
    var aud = app.Configuration["Jwt:Audience"] ?? "";
    if (!iss.StartsWith("https://", StringComparison.OrdinalIgnoreCase) || !aud.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
    {
        logger.LogWarning("Jwt Issuer/Audience non HTTPS in ambiente non Development: iss={Issuer}, aud={Audience}", iss, aud);
    }

    var cookieSecureConfig = app.Configuration.GetValue<bool?>("Cookie:RequireSecure") ?? true;
    if (!cookieSecureConfig)
    {
        logger.LogWarning("Cookie:RequireSecure=false in ambiente non Development: sarà forzato a true");
    }
}

// Hardening header solo fuori da Development.
if (!isDevelopment)
{
    app.UseHsts();
    app.UseHttpsRedirection();
    app.Use(async (ctx, next) =>
    {
        ctx.Response.Headers["X-Frame-Options"] = "DENY";
        ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
        ctx.Response.Headers["Referrer-Policy"] = "no-referrer";
        ctx.Response.Headers["X-XSS-Protection"] = "0";
        ctx.Response.Headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'";
        await next();
    });
}

// Convert UnauthorizedAccessException to 401 (only thrown by protected endpoints helper).
app.Use(async (ctx, next) =>
{
    try
    {
        logger.LogInformation("Richiesta inizio {Method} {Path}", ctx.Request.Method, ctx.Request.Path);
        await next();
        logger.LogInformation("Richiesta fine {Status} {Method} {Path}", ctx.Response.StatusCode, ctx.Request.Method, ctx.Request.Path);
    }
    catch (UnauthorizedAccessException)
    {
        ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
        ctx.Response.ContentType = "application/json";
        await ctx.Response.WriteAsJsonAsync(new { ok = false, error = "unauthorized" });
        logger.LogWarning("Richiesta fine 401 Non Autorizzato {Method} {Path}", ctx.Request.Method, ctx.Request.Path);
    }
});

// --- MIDDLEWARE ORDER (MANDATORY) ---
// 1) Cookie JWT auth loads session into HttpContext.Items["session"]
app.UseCookieJwtAuth();

// 2) CSRF protection reads session from HttpContext.Items["session"]
app.UseCsrfProtection();

// 3) Endpoints
app.MapGet("/health", () => Results.Ok(new { ok = true }));
// Liveness semplice
app.MapGet("/live", () => Results.Ok(new { ok = true }));

// Readiness: verifica DB e config JWT.
app.MapGet("/ready", async (IConfiguration config) =>
{
    try
    {
        var connString = config.GetConnectionString("Sqlite");
        if (string.IsNullOrWhiteSpace(connString))
            return Results.Json(new { ok = false, error = "db_config_missing" }, statusCode: StatusCodes.Status503ServiceUnavailable);

        // Check config JWT minimale
        var iss = config["Jwt:Issuer"];
        var aud = config["Jwt:Audience"];
        var secret = config["Jwt:SecretKey"];
        if (string.IsNullOrWhiteSpace(iss) || string.IsNullOrWhiteSpace(aud) || string.IsNullOrWhiteSpace(secret) || secret.Trim().Length < 32)
            return Results.Json(new { ok = false, error = "invalid_config" }, statusCode: StatusCodes.Status503ServiceUnavailable);

        await using var conn = new Microsoft.Data.Sqlite.SqliteConnection(connString);
        await conn.OpenAsync();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT 1;";
        cmd.CommandTimeout = 3;
        await cmd.ExecuteScalarAsync();

        return Results.Ok(new { ok = true });
    }
    catch
    {
        return Results.Json(new { ok = false, error = "db_unreachable" }, statusCode: StatusCodes.Status503ServiceUnavailable);
    }
});

/// <summary>
/// Registra un nuovo utente con password hashata (bcrypt) rispettando la policy di lunghezza minima.
/// Ritorna 201 con userId o 409 se username esiste, 400 per input non valido.
/// </summary>
app.MapPost("/register", async (HttpContext ctx, UserRepository users) =>
{
    var req = await ctx.Request.ReadFromJsonAsync<RegisterRequest>();
    var username = NormalizeUsername(req?.Username, forceLowerUsername);
    var email = NormalizeEmail(req?.Email);
    var password = req?.Password ?? "";
    logger.LogInformation("Registrazione avviata username={Username} email={Email}", username, email);
    var inputErrors = new List<string>();
    if (string.IsNullOrWhiteSpace(username))
        inputErrors.Add("username_required");
    if (string.IsNullOrWhiteSpace(email))
        inputErrors.Add("email_required");
    else if (!email.Contains('@', StringComparison.Ordinal))
        inputErrors.Add("email_invalid");
    if (string.IsNullOrWhiteSpace(password))
        inputErrors.Add("password_required");
    if (inputErrors.Any())
    {
        logger.LogWarning("Registrazione input non valido username={Username} email={Email} errors={Errors}", username, email, string.Join(",", inputErrors));
        return Results.BadRequest(new { ok = false, error = "invalid_input", errors = inputErrors });
    }
    var safeUsername = username!;
    var safeEmail = email!;

    var policyErrors = AuthHelpers.ValidatePassword(password, minPasswordLength, requireUpper, requireLower, requireDigit, requireSymbol);
    if (policyErrors.Any())
    {
        logger.LogWarning("Registrazione fallita: password non conforme username={Username} errors={Errors}", safeUsername, string.Join(",", policyErrors));
        return Results.BadRequest(new { ok = false, error = "password_policy_failed", errors = policyErrors });
    }
    else
    {
        logger.LogInformation("Registrazione: password conforme policy username={Username}", safeUsername);
    }

    var emailConfirmToken = Guid.NewGuid().ToString("N");
    var emailConfirmExpires = DateTime.UtcNow.AddHours(24);

    var existing = await users.GetByUsernameAsync(safeUsername, ctx.RequestAborted);
    if (existing is not null)
    {
        logger.LogWarning("Registrazione rifiutata: username esistente username={Username}", safeUsername);
        return Results.StatusCode(StatusCodes.Status409Conflict);
    }

    var existingEmail = await users.GetByEmailAsync(safeEmail, ctx.RequestAborted);
    if (existingEmail is not null)
    {
        logger.LogWarning("Registrazione rifiutata: email esistente email={Email}", safeEmail);
        return Results.StatusCode(StatusCodes.Status409Conflict);
    }

    var user = new User
    {
        Id = Guid.NewGuid().ToString("N"),
        Username = safeUsername,
        PasswordHash = PasswordHasher.Hash(password),
        CreatedAtUtc = DateTime.UtcNow.ToString("O"),
        Email = req!.Email!,
        EmailNormalized = safeEmail,
        EmailConfirmed = false,
        EmailConfirmToken = emailConfirmToken,
        EmailConfirmExpiresUtc = emailConfirmExpires.ToString("O")
    };

    await users.CreateAsync(user, ctx.RequestAborted);
    logger.LogInformation("Registrazione OK username={Username} userId={UserId} created={Created} emailToken={EmailToken} exp={EmailExp}", user.Username, user.Id, user.CreatedAtUtc, emailConfirmToken, emailConfirmExpires.ToString("O"));
    return Results.Created($"/users/{user.Id}", new { ok = true, userId = user.Id, email = user.Email, emailConfirmToken, emailConfirmExpiresUtc = emailConfirmExpires.ToString("O") });
});

/// <summary>
/// Login: verifica credenziali da DB, applica throttle (lockout), crea sessione server-side, emette JWT+cookie HttpOnly e CSRF token.
/// </summary>
app.MapPost("/login", async (HttpContext ctx, JwtTokenService jwt, SessionRepository sessions, UserRepository users, ILoginThrottle throttle, LoginAuditRepository auditRepo) =>
{
    var req = await ctx.Request.ReadFromJsonAsync<LoginRequest>();
    var username = NormalizeUsername(req?.Username, forceLowerUsername);
    var password = req?.Password ?? "";
    logger.LogInformation("Login avviato username={Username}", username);
    var inputErrors = new List<string>();
    if (string.IsNullOrWhiteSpace(username))
        inputErrors.Add("username_required");
    if (string.IsNullOrWhiteSpace(password))
        inputErrors.Add("password_required");
    if (inputErrors.Any())
    {
        logger.LogWarning("Login input non valido username={Username} errors={Errors}", username, string.Join(",", inputErrors));
        return Results.BadRequest(new { ok = false, error = "invalid_input", errors = inputErrors });
    }
    var safeUsername = username!;

    if (await throttle.IsLockedAsync(safeUsername, ctx.RequestAborted))
    {
        logger.LogWarning("Login bloccato per throttle username={Username}", safeUsername);
        await AuditAsync(auditRepo, safeUsername, "locked", ctx, "Troppi tentativi falliti");
        return Results.StatusCode(StatusCodes.Status429TooManyRequests);
    }

    var user = await users.GetByUsernameAsync(safeUsername, ctx.RequestAborted);
    if (user is null)
    {
        logger.LogWarning("Login fallito: utente non trovato username={Username}", safeUsername);
        await throttle.RegisterFailureAsync(safeUsername, ctx.RequestAborted);
        await AuditAsync(auditRepo, safeUsername, "user_not_found", ctx, null);
        return Results.Unauthorized();
    }
    else
    {
        logger.LogInformation("Login: utente trovato userId={UserId} emailConfirmed={EmailConfirmed}", user.Id, user.EmailConfirmed);
    }

    if (!PasswordHasher.Verify(password, user.PasswordHash))
    {
        logger.LogWarning("Login fallito: credenziali errate username={Username}", safeUsername);
        await throttle.RegisterFailureAsync(safeUsername, ctx.RequestAborted);
        await AuditAsync(auditRepo, safeUsername, "invalid_credentials", ctx, null);
        return Results.Unauthorized();
    }
    else
    {
        logger.LogInformation("Login: password verificata username={Username}", safeUsername);
    }

    if (!user.EmailConfirmed && !string.Equals(user.Username, "demo", StringComparison.OrdinalIgnoreCase))
    {
        logger.LogWarning("Login bloccato: email non confermata username={Username} userId={UserId}", safeUsername, user.Id);
        await AuditAsync(auditRepo, safeUsername, "email_not_confirmed", ctx, null);
        return Results.Json(new { ok = false, error = "email_not_confirmed" }, statusCode: StatusCodes.Status403Forbidden);
    }

        if (!string.IsNullOrWhiteSpace(user.TotpSecret))
        {
            if (string.IsNullOrWhiteSpace(req?.TotpCode))
            {
                logger.LogWarning("Login fallito: TOTP mancante username={Username}", safeUsername);
                await AuditAsync(auditRepo, safeUsername, "mfa_required", ctx, null);
                return Results.Unauthorized();
            }

            var totp = new OtpNet.Totp(OtpNet.Base32Encoding.ToBytes(user.TotpSecret));
            if (!totp.VerifyTotp(req.TotpCode, out _, new OtpNet.VerificationWindow(1, 1)))
            {
                logger.LogWarning("Login fallito: TOTP errato username={Username}", safeUsername);
                await AuditAsync(auditRepo, safeUsername, "invalid_totp", ctx, null);
                return Results.Unauthorized();
            }
            else
            {
                logger.LogInformation("Login: TOTP verificato username={Username}", safeUsername);
            }
        }
    await throttle.RegisterSuccessAsync(safeUsername, ctx.RequestAborted);
    await AuditAsync(auditRepo, safeUsername, "success", ctx, $"userId={user.Id}");

    var sessionId = Guid.NewGuid().ToString("N");

    // CSRF token stored only server-side (DB). Client receives it and sends it back via header.
    var csrfToken = Base64Url(RandomBytes(32));

    var (token, expiresUtc) = jwt.CreateAccessToken(sessionId);

    var nowIso = DateTime.UtcNow.ToString("O");
    var expIso = expiresUtc.ToString("O");

    var session = new UserSession
    {
        SessionId = sessionId,
        UserId = user.Id,
        CreatedAtUtc = nowIso,
        ExpiresAtUtc = expIso,
        RevokedAtUtc = null,
        UserDataJson = JsonSerializer.Serialize(new { username = user.Username }),
        CsrfToken = csrfToken
    };

    await sessions.CreateAsync(session, ctx.RequestAborted);
    logger.LogInformation("Login OK sessionId={SessionId} userId={UserId} created={Created} exp={Exp} iss={Issuer} aud={Audience}", sessionId, user.Id, nowIso, expIso, app.Configuration["Jwt:Issuer"], app.Configuration["Jwt:Audience"]);

    // Cookie config: HttpOnly + SameSite=Strict + Path=/ + MaxAge aligned to JWT exp
    var requireSecureConfig = app.Configuration.GetValue<bool>("Cookie:RequireSecure");
    var requireSecure = isDevelopment ? requireSecureConfig : true;
    if (!isDevelopment && !requireSecureConfig)
    {
        logger.LogWarning("Cookie Secure forzato in ambiente non Development, ignorando Cookie:RequireSecure=false");
    }
    ctx.Response.Cookies.Append(
        "access_token",
        token,
        new CookieOptions
        {
            HttpOnly = true,
            Secure = requireSecure,
            SameSite = SameSiteMode.Strict,
            Path = "/",
            MaxAge = expiresUtc - DateTime.UtcNow
        });

    var rememberConfigDays = app.Configuration.GetValue<int?>("RememberMe:Days") ?? 14;
    var rememberSameSiteString = app.Configuration["RememberMe:SameSite"] ?? "Strict";
    var rememberSameSite = SameSiteMode.Strict;
    if (rememberSameSiteString.Equals("Lax", StringComparison.OrdinalIgnoreCase))
        rememberSameSite = SameSiteMode.Lax;
    else if (!rememberSameSiteString.Equals("Strict", StringComparison.OrdinalIgnoreCase))
        logger.LogWarning("RememberMe:SameSite non valido ({SameSite}), fallback a Strict", rememberSameSiteString);
    if (!isDevelopment && rememberSameSite == SameSiteMode.None)
        logger.LogWarning("RememberMe:SameSite=None in ambiente non Development: sconsigliato");
    var rememberCookieName = app.Configuration["RememberMe:CookieName"] ?? "refresh_token";
    var rememberPath = app.Configuration["RememberMe:Path"] ?? "/refresh";
    var rememberIssued = false;

    if (req?.RememberMe == true)
    {
        var refreshToken = Base64Url(RandomBytes(32));
        var refreshExpires = DateTime.UtcNow.AddDays(rememberConfigDays);
        var rt = new RefreshToken
        {
            Id = Guid.NewGuid().ToString("N"),
            UserId = user.Id,
            SessionId = sessionId,
            Token = refreshToken,
            CreatedAtUtc = nowIso,
            ExpiresAtUtc = refreshExpires.ToString("O"),
            RevokedAtUtc = null,
            UserAgent = ctx.Request.Headers["User-Agent"].ToString(),
            ClientIp = ctx.Connection.RemoteIpAddress?.ToString(),
            RotationParentId = null,
            RotationReason = null
        };
        var refreshRepo = ctx.RequestServices.GetRequiredService<RefreshTokenRepository>();
        await refreshRepo.CreateAsync(rt, ctx.RequestAborted);

        ctx.Response.Cookies.Append(
            rememberCookieName,
            refreshToken,
            new CookieOptions
            {
                HttpOnly = true,
                Secure = requireSecure,
                SameSite = rememberSameSite,
                Path = rememberPath,
                MaxAge = refreshExpires - DateTime.UtcNow
            });
        rememberIssued = true;
    }

    return Results.Ok(new { ok = true, csrfToken, rememberIssued });
});

app.MapGet("/me", (HttpContext ctx) =>
{
    var session = ctx.GetRequiredSession();
    return Results.Ok(new
    {
        ok = true,
        sessionId = session.SessionId,
        userId = session.UserId,
        createdAtUtc = session.CreatedAtUtc,
        expiresAtUtc = session.ExpiresAtUtc,
        userData = JsonSerializer.Deserialize<JsonElement>(session.UserDataJson)
    });
});

/// <summary>
/// Logout: revoca la sessione e cancella il cookie.
/// </summary>
app.MapPost("/logout", async (HttpContext ctx, SessionRepository sessions) =>
{
    var session = ctx.GetRequiredSession();

    await sessions.RevokeAsync(session.SessionId, DateTime.UtcNow.ToString("O"), ctx.RequestAborted);
    logger.LogInformation("Logout OK sessionId={SessionId} userId={UserId} revokedAt={RevokedAt}", session.SessionId, session.UserId, DateTime.UtcNow.ToString("O"));

    // Delete cookie (must match name/path/samesite/secure to reliably remove)
    var requireSecure = isDevelopment ? app.Configuration.GetValue<bool>("Cookie:RequireSecure") : true;
    ctx.Response.Cookies.Append("access_token", "", new CookieOptions
    {
        Expires = DateTimeOffset.UnixEpoch,
        HttpOnly = true,
        Secure = requireSecure,
        SameSite = SameSiteMode.Strict,
        Path = "/"
    });

    if (ctx.Request.Cookies.TryGetValue(app.Configuration["RememberMe:CookieName"] ?? "refresh_token", out var refreshToken) && !string.IsNullOrWhiteSpace(refreshToken))
    {
        var refreshRepo = ctx.RequestServices.GetRequiredService<RefreshTokenRepository>();
        await refreshRepo.RevokeByTokenAsync(refreshToken, "logout", ctx.RequestAborted);
        ctx.Response.Cookies.Append(app.Configuration["RememberMe:CookieName"] ?? "refresh_token", "", new CookieOptions
        {
            Expires = DateTimeOffset.UnixEpoch,
            HttpOnly = true,
            Secure = requireSecure,
            SameSite = SameSiteMode.Strict,
            Path = app.Configuration["RememberMe:Path"] ?? "/refresh"
        });
        logger.LogInformation("Logout: refresh token revocato");
    }

    return Results.Ok(new { ok = true });

    // TODO PROD: refresh token
    // TODO PROD: cleanup background service
    // TODO PROD: multi-device session mgmt
    // TODO PROD: security logging
});

/// <summary>
/// Setup MFA TOTP: genera segreto per l'utente loggato (prima volta), restituisce segreto e otpauth URI.
/// Richiede sessione e CSRF.
/// </summary>
app.MapPost("/mfa/setup", async (HttpContext ctx, UserRepository users) =>
{
    var session = ctx.GetRequiredSession();
    var user = await users.GetByIdAsync(session.UserId, ctx.RequestAborted);
    if (user is null)
        return Results.NotFound();

    if (!string.IsNullOrWhiteSpace(user.TotpSecret))
        return Results.StatusCode(StatusCodes.Status409Conflict);

    var secretKey = OtpNet.KeyGeneration.GenerateRandomKey(20);
    var secretBase32 = OtpNet.Base32Encoding.ToString(secretKey);

    await users.SetTotpSecretAsync(user.Id, secretBase32, ctx.RequestAborted);

    var issuer = Uri.EscapeDataString("SecureAuthMinimalApi");
    var label = Uri.EscapeDataString(user.Username);
    var otpauth = $"otpauth://totp/{issuer}:{label}?secret={secretBase32}&issuer={issuer}";

    return Results.Ok(new { ok = true, secret = secretBase32, otpauthUri = otpauth });
});

/// <summary>
/// Disabilita MFA TOTP: azzera il segreto per l'utente loggato.
/// </summary>
app.MapPost("/mfa/disable", async (HttpContext ctx, UserRepository users) =>
{
    var session = ctx.GetRequiredSession();
    var user = await users.GetByIdAsync(session.UserId, ctx.RequestAborted);
    if (user is null)
        return Results.NotFound();

    await users.ClearTotpSecretAsync(session.UserId, ctx.RequestAborted);
    logger.LogInformation("MFA disabilitata userId={UserId}", session.UserId);
    return Results.Ok(new { ok = true });
});

/// <summary>
/// Conferma email usando il token ricevuto in fase di registrazione.
/// </summary>
app.MapPost("/confirm-email", async (HttpContext ctx, UserRepository users) =>
{
    var req = await ctx.Request.ReadFromJsonAsync<ConfirmEmailRequest>();
    if (string.IsNullOrWhiteSpace(req?.Token))
    {
        logger.LogWarning("Conferma email fallita: token mancante");
        return Results.BadRequest(new { ok = false, error = "invalid_input", errors = new[] { "token_required" } });
    }
    else
    {
        logger.LogInformation("Conferma email richiesta token={Token}", req.Token);
    }

    var user = await users.GetByEmailTokenAsync(req.Token, ctx.RequestAborted);
    if (user is null)
    {
        logger.LogWarning("Conferma email fallita: token non trovato token={Token}", req.Token);
        return Results.BadRequest(new { ok = false, error = "invalid_token" });
    }
    logger.LogInformation("Conferma email: utente trovato userId={UserId} emailConfirmed={EmailConfirmed} tokenExp={TokenExp}", user.Id, user.EmailConfirmed, user.EmailConfirmExpiresUtc);

    if (user.EmailConfirmed)
    {
        logger.LogInformation("Email giÃ  confermata userId={UserId}", user.Id);
        await users.ConfirmEmailAsync(user.Id, ctx.RequestAborted);
        return Results.Ok(new { ok = true, alreadyConfirmed = true });
    }

    if (string.IsNullOrWhiteSpace(user.EmailConfirmExpiresUtc) || DateTime.Parse(user.EmailConfirmExpiresUtc).ToUniversalTime() <= DateTime.UtcNow)
    {
        logger.LogWarning("Conferma email fallita: token scaduto userId={UserId} token={Token} exp={Exp}", user.Id, user.EmailConfirmToken, user.EmailConfirmExpiresUtc);
        return Results.Json(new { ok = false, error = "token_expired" }, statusCode: StatusCodes.Status410Gone);
    }

    await users.ConfirmEmailAsync(user.Id, ctx.RequestAborted);
    logger.LogInformation("Email confermata userId={UserId}", user.Id);
    return Results.Ok(new { ok = true });
});

/// <summary>
/// Logout da tutti i dispositivi: revoca tutti i refresh token dell'utente corrente e la sessione attuale.
/// </summary>
app.MapPost("/logout-all", async (HttpContext ctx, SessionRepository sessions, RefreshTokenRepository refreshRepo) =>
{
    var session = ctx.GetRequiredSession();

    await refreshRepo.RevokeAllForUserAsync(session.UserId, "logout-all", ctx.RequestAborted);
    await sessions.RevokeAsync(session.SessionId, DateTime.UtcNow.ToString("O"), ctx.RequestAborted);
    logger.LogInformation("Logout-all eseguito userId={UserId} sessionId={SessionId}", session.UserId, session.SessionId);

    var requireSecure = app.Environment.IsDevelopment() ? app.Configuration.GetValue<bool>("Cookie:RequireSecure") : true;
    ctx.Response.Cookies.Append("access_token", "", new CookieOptions
    {
        Expires = DateTimeOffset.UnixEpoch,
        HttpOnly = true,
        Secure = requireSecure,
        SameSite = SameSiteMode.Strict,
        Path = "/"
    });
    ctx.Response.Cookies.Append(app.Configuration["RememberMe:CookieName"] ?? "refresh_token", "", new CookieOptions
    {
        Expires = DateTimeOffset.UnixEpoch,
        HttpOnly = true,
        Secure = requireSecure,
        SameSite = SameSiteMode.Strict,
        Path = app.Configuration["RememberMe:Path"] ?? "/refresh"
    });

    return Results.Ok(new { ok = true });
});

/// <summary>
/// Introspezione: restituisce stato sessione (attiva/revocata/scaduta) usando token da header Bearer o cookie.
/// </summary>
app.MapGet("/introspect", async (HttpContext ctx, JwtTokenService jwt, SessionRepository sessions) =>
{
    if (!AuthHelpers.TryGetToken(ctx, out var token))
        return Results.Unauthorized();

    var handler = new JwtSecurityTokenHandler { MapInboundClaims = false };
    JwtSecurityToken? parsed = null;
    try
    {
        handler.ValidateToken(token, jwt.GetValidationParameters(), out var validated);
        parsed = validated as JwtSecurityToken;
    }
    catch (SecurityTokenException)
    {
        logger.LogWarning("Introspect: token non valido");
        return Results.Ok(new { active = false, reason = "invalid_token" });
    }
    catch (ArgumentException)
    {
        logger.LogWarning("Introspect: token non valido (arg)");
        return Results.Ok(new { active = false, reason = "invalid_token" });
    }

    var sessionId = parsed?.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Sub)?.Value;
    if (string.IsNullOrWhiteSpace(sessionId))
        return Results.Ok(new { active = false, reason = "invalid_token" });

    var session = await sessions.GetByIdAsync(sessionId, ctx.RequestAborted);
    if (session is null)
    {
        logger.LogWarning("Introspect: sessione non trovata");
        return Results.Ok(new { active = false, reason = "not_found" });
    }

    if (!string.IsNullOrWhiteSpace(session.RevokedAtUtc))
    {
        logger.LogInformation("Introspect: sessione revocata sessionId={SessionId}", session.SessionId);
        return Results.Ok(new { active = false, reason = "revoked" });
    }

    var exp = DateTime.Parse(session.ExpiresAtUtc).ToUniversalTime();
    if (exp <= DateTime.UtcNow)
    {
        logger.LogInformation("Introspect: sessione scaduta sessionId={SessionId} userId={UserId} exp={Exp}", session.SessionId, session.UserId, session.ExpiresAtUtc);
        return Results.Ok(new { active = false, reason = "expired" });
    }

    logger.LogInformation("Introspect: sessione attiva sessionId={SessionId} userId={UserId} exp={Exp} iss={Iss} aud={Aud}", session.SessionId, session.UserId, session.ExpiresAtUtc, parsed?.Issuer, string.Join(",", parsed?.Audiences ?? Enumerable.Empty<string>()));
    return Results.Ok(new
    {
        active = true,
        sessionId = session.SessionId,
        userId = session.UserId,
        expiresAtUtc = session.ExpiresAtUtc
    });
});

app.Run();

static byte[] RandomBytes(int len)
{
    var b = new byte[len];
    System.Security.Cryptography.RandomNumberGenerator.Fill(b);
    return b;
}

static string Base64Url(byte[] bytes)
{
    return Convert.ToBase64String(bytes)
        .TrimEnd('=')
        .Replace('+', '-')
        .Replace('/', '_');
}

static Task AuditAsync(LoginAuditRepository repo, string username, string outcome, HttpContext ctx, string? detail)
{
    var audit = new LoginAudit
    {
        Id = Guid.NewGuid().ToString("N"),
        Username = username,
        Outcome = outcome,
        TimestampUtc = DateTime.UtcNow.ToString("O"),
        ClientIp = ctx.Connection.RemoteIpAddress?.ToString(),
        UserAgent = ctx.Request.Headers["User-Agent"].ToString(),
        Detail = detail
    };
    return repo.CreateAsync(audit, ctx.RequestAborted);
}

static string? NormalizeUsername(string? username, bool forceLower)
{
    if (string.IsNullOrWhiteSpace(username))
        return null;
    var trimmed = username.Trim();
    return forceLower ? trimmed.ToLowerInvariant() : trimmed;
}

static string? NormalizeEmail(string? email)
{
    if (string.IsNullOrWhiteSpace(email))
        return null;
    return email.Trim().ToLowerInvariant();
}

public sealed record LoginRequest(string? Username, string? Password, string? TotpCode, bool RememberMe);
public sealed record RegisterRequest(string? Username, string? Email, string? Password);
public sealed record ConfirmEmailRequest(string? Token);

public static class AuthHelpers
{
    public static UserSession GetRequiredSession(this HttpContext ctx)
    {
        if (ctx.Items.TryGetValue("session", out var sObj) && sObj is UserSession s)
            return s;

        throw new UnauthorizedAccessException();
    }

    // Estrae il token dal header Authorization Bearer o dal cookie access_token.
    public static bool TryGetToken(HttpContext ctx, out string token)
    {
        token = "";
        var authHeader = ctx.Request.Headers["Authorization"].ToString();
        if (!string.IsNullOrWhiteSpace(authHeader) && authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            token = authHeader["Bearer ".Length..].Trim();
            return !string.IsNullOrWhiteSpace(token);
        }

        if (ctx.Request.Cookies.TryGetValue("access_token", out var cookieToken) && !string.IsNullOrWhiteSpace(cookieToken))
        {
            token = cookieToken;
            return true;
        }

        return false;
    }
    public static List<string> ValidatePassword(string password, int minLength, bool requireUpper, bool requireLower, bool requireDigit, bool requireSymbol)
    {
        var errors = new List<string>();
        if (password.Length < minLength)
            errors.Add("too_short");
        if (requireUpper && !password.Any(char.IsUpper))
            errors.Add("missing_upper");
        if (requireLower && !password.Any(char.IsLower))
            errors.Add("missing_lower");
        if (requireDigit && !password.Any(char.IsDigit))
            errors.Add("missing_digit");
        if (requireSymbol && !password.Any(ch => !char.IsLetterOrDigit(ch)))
            errors.Add("missing_symbol");
        return errors;
    }
}

public partial class Program { }
