using System.Text.Json;
using Microsoft.Extensions.Logging;
using SecureAuthMinimalApi.Data;
using SecureAuthMinimalApi.Models;
using SecureAuthMinimalApi.Options;
using SecureAuthMinimalApi.Services;
using static SecureAuthMinimalApi.Endpoints.EndpointUtilities;
using System.Security.Cryptography;
using System.Text;

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
        bool emailConfirmationRequired,
        int mfaChallengeMinutes,
        bool mfaRequireUaMatch,
        bool mfaRequireIpMatch,
        int mfaMaxAttempts)
    {
        var isDevelopment = app.Environment.IsDevelopment();
        var rememberOptions = app.Services.GetRequiredService<Microsoft.Extensions.Options.IOptions<RememberMeOptions>>().Value;
        var deviceOptions = app.Services.GetRequiredService<Microsoft.Extensions.Options.IOptions<DeviceOptions>>().Value;
        var refreshOptions = app.Services.GetRequiredService<Microsoft.Extensions.Options.IOptions<SecureAuthMinimalApi.Services.RefreshOptions>>().Value;

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

            if (emailConfirmationRequired && !user.EmailConfirmed && !string.Equals(user.Username, "demo", StringComparison.OrdinalIgnoreCase))
            {
                logger.LogWarning("Login bloccato: email non confermata username={Username} userId={UserId}", safeUsername, user.Id);
                await AuditAsync(auditRepo, safeUsername, "email_not_confirmed", ctx, null);
                return Results.Json(new { ok = false, error = "email_not_confirmed" }, statusCode: StatusCodes.Status403Forbidden);
            }
            else if (!emailConfirmationRequired && !user.EmailConfirmed)
            {
                logger.LogInformation("Login: email non confermata ma requisito disabilitato username={Username} userId={UserId}", safeUsername, user.Id);
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

            var rememberSameSite = ParseSameSite(rememberOptions.SameSite, rememberOptions.AllowSameSiteNone, isDevelopment, logger, "RememberMe");
            var rememberCookieName = rememberOptions.CookieName ?? "refresh_token";
            var rememberPath = rememberOptions.Path ?? "/refresh";
            var rememberConfigDays = rememberOptions.Days <= 0 ? 14 : rememberOptions.Days;
            var rememberRequireSecure = isDevelopment ? rememberOptions.RequireSecure : true;
            if (!isDevelopment && !rememberOptions.RequireSecure)
            {
                logger.LogWarning("RememberMe:RequireSecure=false in ambiente non Development: forzato a true");
            }

            var refreshSameSiteValue = string.IsNullOrWhiteSpace(refreshOptions.SameSite) ? rememberOptions.SameSite : refreshOptions.SameSite;
            var refreshSameSite = ParseSameSite(refreshSameSiteValue, refreshOptions.AllowSameSiteNone || rememberOptions.AllowSameSiteNone, isDevelopment, logger, "Refresh");
            var refreshCookieName = refreshOptions.CookieName ?? rememberCookieName;
            var refreshPath = refreshOptions.Path ?? rememberPath;
            var refreshRequireSecure = isDevelopment ? refreshOptions.RequireSecure : true;
            if (!isDevelopment && !refreshOptions.RequireSecure)
            {
                logger.LogWarning("Refresh:RequireSecure=false in ambiente non Development: forzato a true");
            }

            var deviceCookieName = deviceOptions.CookieName ?? "device_id";
            var deviceSameSite = ParseSameSite(deviceOptions.SameSite, deviceOptions.AllowSameSiteNone, isDevelopment, logger, "Device");
            var deviceRequireSecure = isDevelopment ? deviceOptions.RequireSecure : true;
            if (!isDevelopment && !deviceOptions.RequireSecure)
            {
                logger.LogWarning("Device:RequireSecure=false in ambiente non Development: forzato a true");
            }
            var devicePersistDays = deviceOptions.PersistDays <= 0 ? rememberConfigDays : deviceOptions.PersistDays;
            var rememberIssued = false;
            var deviceIssued = false;
            string? deviceId = null;
            string? refreshExpiresUtc = null;
            string? refreshCsrfToken = null;

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
                refreshCsrfToken = Base64Url(RandomBytes(32));
                var refreshCsrfHash = HashToken(refreshCsrfToken);
                var refreshExpires = DateTime.UtcNow.AddDays(rememberConfigDays);
                var rt = new RefreshToken
                {
                    Id = Guid.NewGuid().ToString("N"),
                    UserId = user.Id,
                    SessionId = sessionId,
                    Token = refreshToken,
                    TokenHash = null,
                    RefreshCsrfHash = refreshCsrfHash,
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
                    refreshCookieName,
                    refreshToken,
                    new CookieOptions
                    {
                        HttpOnly = true,
                        Secure = refreshRequireSecure,
                        SameSite = refreshSameSite,
                        Path = refreshPath,
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
            return Results.Ok(new { ok = true, csrfToken, rememberIssued, deviceIssued, deviceId, refreshExpiresAtUtc = refreshExpiresUtc, idToken, refreshCsrfToken });
        });
    }

    private static SameSiteMode ParseSameSite(string? value, bool allowNone, bool isDevelopment, ILogger logger, string context)
    {
        var sameSiteString = string.IsNullOrWhiteSpace(value) ? "Strict" : value;
        var sameSite = SameSiteMode.Strict;
        if (sameSiteString.Equals("Lax", StringComparison.OrdinalIgnoreCase))
            sameSite = SameSiteMode.Lax;
        else if (sameSiteString.Equals("None", StringComparison.OrdinalIgnoreCase))
            sameSite = SameSiteMode.None;
        else if (!sameSiteString.Equals("Strict", StringComparison.OrdinalIgnoreCase))
            logger.LogWarning("{Context}:SameSite non valido ({SameSite}), fallback a Strict", context, sameSiteString);

        if (!isDevelopment && sameSite == SameSiteMode.None && !allowNone)
        {
            logger.LogWarning("{Context}:SameSite=None in ambiente non Development non consentito: forzato a Strict (abilita {Context}:AllowSameSiteNone per override esplicito)", context, sameSiteString);
            sameSite = SameSiteMode.Strict;
        }

        return sameSite;
    }

    private static string HashToken(string token)
    {
        using var sha = SHA256.Create();
        var bytes = Encoding.UTF8.GetBytes(token);
        var hash = sha.ComputeHash(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
