using System.Text.Json;
using Microsoft.Extensions.Logging;
using SecureAuthMinimalApi.Data;
using SecureAuthMinimalApi.Models;
using SecureAuthMinimalApi.Services;
using static SecureAuthMinimalApi.Endpoints.EndpointUtilities;

namespace SecureAuthMinimalApi.Endpoints;

public static class LoginEndpoints
{
    /// <summary>
    /// Mappa l'endpoint di login gestendo throttle, MFA e rilascio di sessioni e cookie.
    /// </summary>
    public static void MapLogin(
        this WebApplication app,
        ILogger logger,
        bool forceLowerUsername,
        int mfaChallengeMinutes,
        bool mfaRequireUaMatch,
        bool mfaRequireIpMatch,
        int mfaMaxAttempts)
    {
        var isDevelopment = app.Environment.IsDevelopment();

        app.MapPost("/login", async (HttpContext ctx, JwtTokenService jwt, IdTokenService idTokenService, SessionRepository sessions, UserRepository users, ILoginThrottle throttle, LoginAuditRepository auditRepo) =>
        {
            var req = await ctx.Request.ReadFromJsonAsync<LoginRequest>();
            var username = NormalizeUsername(req?.Username, forceLowerUsername);
            var password = req?.Password ?? "";
            var nonce = req?.Nonce;
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
                logger.LogInformation("MFA richiesto: generazione challenge per username={Username}", safeUsername);
                var challengeId = Guid.NewGuid().ToString("N");
                var now = DateTime.UtcNow;
                var challenge = new MfaChallenge
                {
                    Id = challengeId,
                    UserId = user.Id,
                    CreatedAtUtc = now.ToString("O"),
                    ExpiresAtUtc = now.AddMinutes(mfaChallengeMinutes).ToString("O"),
                    UsedAtUtc = null,
                    UserAgent = ctx.Request.Headers["User-Agent"].ToString(),
                    ClientIp = ctx.Connection.RemoteIpAddress?.ToString(),
                    AttemptCount = 0
                };
                var challengeRepo = ctx.RequestServices.GetRequiredService<MfaChallengeRepository>();
                await challengeRepo.CreateAsync(challenge, ctx.RequestAborted);
                await AuditAsync(auditRepo, safeUsername, "mfa_required", ctx, null);
                return Results.Json(new { ok = false, error = "mfa_required", challengeId }, statusCode: StatusCodes.Status401Unauthorized);
            }
            await throttle.RegisterSuccessAsync(safeUsername, ctx.RequestAborted);
            await AuditAsync(auditRepo, safeUsername, "success", ctx, $"userId={user.Id}");

            var sessionId = Guid.NewGuid().ToString("N");
            var csrfToken = Base64Url(RandomBytes(32));
            var (token, expiresUtc) = jwt.CreateAccessToken(sessionId);
            var (idToken, _) = idTokenService.CreateIdToken(
                user.Id,
                user.Username,
                user.Email,
                mfaConfirmed: false,
                nonce: nonce,
                name: user.Name,
                givenName: user.GivenName,
                familyName: user.FamilyName,
                pictureUrl: user.PictureUrl);

            var nowIso = DateTime.UtcNow.ToString("O");
            var expIso = expiresUtc.ToString("O");

            var session = new UserSession
            {
                SessionId = sessionId,
                UserId = user.Id,
                CreatedAtUtc = nowIso,
                ExpiresAtUtc = expIso,
                RevokedAtUtc = null,
                UserDataJson = JsonSerializer.Serialize(new
                {
                    username = user.Username,
                    name = user.Name,
                    given_name = user.GivenName,
                    family_name = user.FamilyName,
                    email = user.Email,
                    picture = user.PictureUrl
                }),
                CsrfToken = csrfToken,
                LastSeenUtc = nowIso
            };

            await sessions.CreateAsync(session, ctx.RequestAborted);
            logger.LogInformation("Login OK sessionId={SessionId} userId={UserId} created={Created} exp={Exp} iss={Issuer} aud={Audience}", sessionId, user.Id, nowIso, expIso, app.Configuration["Jwt:Issuer"], app.Configuration["Jwt:Audience"]);

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
            var deviceCookieName = app.Configuration["Device:CookieName"] ?? "device_id";
            var deviceSameSiteString = app.Configuration["Device:SameSite"] ?? "Strict";
            var deviceSameSite = SameSiteMode.Strict;
            if (deviceSameSiteString.Equals("Lax", StringComparison.OrdinalIgnoreCase))
                deviceSameSite = SameSiteMode.Lax;
            else if (deviceSameSiteString.Equals("None", StringComparison.OrdinalIgnoreCase))
                deviceSameSite = SameSiteMode.None;
            else if (!deviceSameSiteString.Equals("Strict", StringComparison.OrdinalIgnoreCase))
                logger.LogWarning("Device:SameSite non valido ({SameSite}), fallback a Strict", deviceSameSiteString);
            if (!isDevelopment && deviceSameSite == SameSiteMode.None)
                logger.LogWarning("Device:SameSite=None in ambiente non Development: sconsigliato");
            var deviceRequireSecureConfig = app.Configuration.GetValue<bool?>("Device:RequireSecure");
            var deviceRequireSecure = isDevelopment
                ? (deviceRequireSecureConfig ?? (app.Configuration.GetValue<bool?>("Cookie:RequireSecure") ?? false))
                : true;
            var devicePersistDays = app.Configuration.GetValue<int?>("Device:PersistDays") ?? rememberConfigDays;
            var rememberIssued = false;
            var deviceIssued = false;
            string? deviceId = null;
            string? refreshExpiresUtc = null;

            if (req?.RememberMe == true)
            {
                if (!ctx.Request.Cookies.TryGetValue(deviceCookieName, out var existingDeviceId) || string.IsNullOrWhiteSpace(existingDeviceId))
                {
                    deviceId = Base64Url(RandomBytes(32));
                    deviceIssued = true;
                }
                else
                {
                    deviceId = existingDeviceId;
                }

                var refreshToken = Base64Url(RandomBytes(32));
                var refreshExpires = DateTime.UtcNow.AddDays(rememberConfigDays);
                var rt = new RefreshToken
                {
                    Id = Guid.NewGuid().ToString("N"),
                    UserId = user.Id,
                    SessionId = sessionId,
                    Token = refreshToken,
                    TokenHash = null,
                    CreatedAtUtc = nowIso,
                    ExpiresAtUtc = refreshExpires.ToString("O"),
                    RevokedAtUtc = null,
                    UserAgent = ctx.Request.Headers["User-Agent"].ToString(),
                    ClientIp = ctx.Connection.RemoteIpAddress?.ToString(),
                    DeviceId = deviceId,
                    DeviceLabel = null,
                    RotationParentId = null,
                    RotationReason = null
                };
                var refreshRepo = ctx.RequestServices.GetRequiredService<RefreshTokenRepository>();
                await refreshRepo.CreateAsync(rt, ctx.RequestAborted);
                refreshExpiresUtc = refreshExpires.ToString("O");

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
                ctx.Response.Cookies.Append(
                    deviceCookieName,
                    deviceId!,
                    new CookieOptions
                    {
                        HttpOnly = true,
                        Secure = deviceRequireSecure,
                        SameSite = deviceSameSite,
                        Path = "/",
                        MaxAge = TimeSpan.FromDays(devicePersistDays)
                    });
                rememberIssued = true;
            }

            ctx.Response.Headers.CacheControl = "no-store";
            return Results.Ok(new { ok = true, csrfToken, rememberIssued, deviceIssued, deviceId, refreshExpiresAtUtc = refreshExpiresUtc, idToken });
        });
    }
}
