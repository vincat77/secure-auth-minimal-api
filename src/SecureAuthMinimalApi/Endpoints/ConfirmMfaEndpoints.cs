using System.Text.Json;
using SecureAuthMinimalApi.Data;
using SecureAuthMinimalApi.Models;
using SecureAuthMinimalApi.Options;
using SecureAuthMinimalApi.Services;
using static SecureAuthMinimalApi.Endpoints.EndpointUtilities;
using static SecureAuthMinimalApi.Utilities.SecurityUtils;
using static SecureAuthMinimalApi.Utilities.CookieUtils;
using Microsoft.Extensions.Options;
using SecureAuthMinimalApi.Logging;

namespace SecureAuthMinimalApi.Endpoints;

public static class ConfirmMfaEndpoints
{
    /// <summary>
    /// Mappa l'endpoint di conferma MFA che valida la challenge e rilascia una nuova sessione.
    /// </summary>
    public static void MapConfirmMfa(
        this WebApplication app,
        LoginOptions loginOptions)
    {
        var isDevelopment = app.Environment.IsDevelopment();
        var rememberOptions = app.Services.GetRequiredService<IOptions<RememberMeOptions>>().Value;
        var deviceOptions = app.Services.GetRequiredService<IOptions<DeviceOptions>>().Value;
        var refreshOptions = app.Services.GetRequiredService<IOptions<RefreshOptions>>().Value;
        var cookieConfig = app.Services.GetRequiredService<IOptions<CookieConfigOptions>>().Value;

        app.MapPost("/login/confirm-mfa", async (HttpContext ctx, JwtTokenService jwt, IdTokenService idTokenService, SessionRepository sessions, UserRepository users, MfaChallengeRepository challenges, LoginAuditRepository auditRepo, ILogger<ConfirmMfaLogger> logger) =>
        {
            var body = await ctx.Request.ReadFromJsonAsync<ConfirmMfaRequest>();
            if (string.IsNullOrWhiteSpace(body?.ChallengeId) || string.IsNullOrWhiteSpace(body.TotpCode))
            {
                return Results.BadRequest(new { ok = false, error = "invalid_input" });
            }

            var challenge = await challenges.GetByIdAsync(body.ChallengeId, ctx.RequestAborted);
            if (challenge is null)
            {
                logger.LogWarning("Confirm MFA: challenge non trovato challengeId={ChallengeId}", body.ChallengeId);
                return Results.Unauthorized();
            }

            if (!DateTime.TryParse(challenge.ExpiresAtUtc, out var exp) || exp.ToUniversalTime() <= DateTime.UtcNow)
            {
                logger.LogWarning("Confirm MFA: challenge scaduto challengeId={ChallengeId} exp={Exp}", body.ChallengeId, challenge.ExpiresAtUtc);
                return Results.Unauthorized();
            }

            if (!string.IsNullOrWhiteSpace(challenge.UsedAtUtc))
            {
                logger.LogWarning("Confirm MFA: challenge gia usato challengeId={ChallengeId}", body.ChallengeId);
                return Results.Unauthorized();
            }

            var ua = ctx.Request.Headers["User-Agent"].ToString();
            if (loginOptions.MfaRequireUaMatch && !string.Equals(ua, challenge.UserAgent, StringComparison.Ordinal))
            {
                logger.LogWarning("Confirm MFA: UA mismatch atteso={Expected} actual={Actual}", challenge.UserAgent, ua);
                return Results.Unauthorized();
            }

            if (loginOptions.MfaRequireIpMatch)
            {
                var reqIp = ctx.Request.Headers["X-Forwarded-For"].FirstOrDefault() ?? ctx.Connection.RemoteIpAddress?.ToString();
                if (!string.Equals(reqIp, challenge.ClientIp, StringComparison.Ordinal))
                {
                    logger.LogWarning("Confirm MFA: IP mismatch atteso={Expected} actual={Actual}", challenge.ClientIp, reqIp);
                    return Results.Unauthorized();
                }
            }

            if (challenge.AttemptCount >= loginOptions.MfaMaxAttempts)
            {
                logger.LogWarning("Confirm MFA: max tentativi raggiunti challengeId={ChallengeId}", challenge.Id);
                return Results.Unauthorized();
            }

            var user = await users.GetByIdAsync(challenge.UserId, ctx.RequestAborted);
            if (user is null || string.IsNullOrWhiteSpace(user.TotpSecret))
            {
                logger.LogWarning("Confirm MFA: utente o TOTP non trovati userId={UserId}", challenge.UserId);
                return Results.Unauthorized();
            }

            var totp = new OtpNet.Totp(OtpNet.Base32Encoding.ToBytes(user.TotpSecret));
            if (!totp.VerifyTotp(body.TotpCode, out _, new OtpNet.VerificationWindow(1, 1)))
            {
                logger.LogWarning("Confirm MFA: TOTP errato challengeId={ChallengeId} userId={UserId}", challenge.Id, user.Id);
                await challenges.IncrementAttemptAsync(challenge.Id, ctx.RequestAborted);
                await AuditAsync(auditRepo, user.Username, "invalid_totp", ctx, null);
                return Results.Unauthorized();
            }

            await challenges.MarkUsedAsync(challenge.Id, ctx.RequestAborted);
            await AuditAsync(auditRepo, user.Username, "mfa_confirmed", ctx, null);

            var sessionId = Guid.NewGuid().ToString("N");
            var csrfToken = Base64Url(RandomBytes(32));
            var (token, expiresUtc) = jwt.CreateAccessToken(sessionId);
            var (idToken, _) = idTokenService.CreateIdToken(
                user.Id,
                user.Username,
                user.Email,
                mfaConfirmed: true,
                nonce: body.Nonce,
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

            var requireSecureConfig = cookieConfig.RequireSecure || refreshOptions.RequireSecure;
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

            var rememberIssued = false;
            string? refreshExpiresUtc = null;
            var deviceIssued = false;
            string? deviceId = null;
            string? refreshCsrfToken = null;

            if (body.RememberMe)
            {
                var rememberConfigDays = rememberOptions.Days <= 0 ? 14 : rememberOptions.Days;
                var refreshSameSiteValue = string.IsNullOrWhiteSpace(refreshOptions.SameSite) ? rememberOptions.SameSite : refreshOptions.SameSite;
                var rememberSameSite = ParseSameSite(refreshSameSiteValue, refreshOptions.AllowSameSiteNone || rememberOptions.AllowSameSiteNone, isDevelopment, logger, "Refresh");
                var rememberPath = refreshOptions.Path ?? rememberOptions.Path ?? "/refresh";
                var refreshToken = Base64Url(RandomBytes(32));
                refreshCsrfToken = Base64Url(RandomBytes(32));
                var refreshCsrfHash = HashToken(refreshCsrfToken);
                var refreshExpires = DateTime.UtcNow.AddDays(rememberConfigDays);
                var refreshRepo = ctx.RequestServices.GetRequiredService<RefreshTokenRepository>();

                var deviceCookieName = deviceOptions.CookieName ?? "device_id";
                if (!ctx.Request.Cookies.TryGetValue(deviceCookieName, out var existingDeviceId) || string.IsNullOrWhiteSpace(existingDeviceId))
                {
                    deviceId = Base64Url(RandomBytes(32));
                    deviceIssued = true;
                }
                else
                {
                    deviceId = existingDeviceId;
                }

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
                await refreshRepo.CreateAsync(rt, ctx.RequestAborted);
                refreshExpiresUtc = refreshExpires.ToString("O");

                var rememberCookieName = refreshOptions.CookieName ?? rememberOptions.CookieName ?? "refresh_token";
                var rememberSecureConfig = refreshOptions.RequireSecure || cookieConfig.RequireSecure;
                var rememberSecure = isDevelopment ? rememberSecureConfig : true;
                if (!isDevelopment && !rememberSecureConfig)
                {
                    logger.LogWarning("Refresh:RequireSecure=false in ambiente non Development: forzato a true");
                    rememberSecure = true;
                }
                ctx.Response.Cookies.Append(
                    rememberCookieName,
                    refreshToken,
                    new CookieOptions
                    {
                        HttpOnly = true,
                        Secure = rememberSecure,
                        SameSite = rememberSameSite,
                        Path = rememberPath,
                        MaxAge = refreshExpires - DateTime.UtcNow
                    });

                var deviceSameSite = ParseSameSite(deviceOptions.SameSite, deviceOptions.AllowSameSiteNone, isDevelopment, logger, "Device");
                var deviceRequireSecureConfig = deviceOptions.RequireSecure || cookieConfig.RequireSecure;
                ctx.Response.Cookies.Append(
                    deviceCookieName,
                    deviceId!,
                    new CookieOptions
                    {
                        HttpOnly = true,
                        Secure = isDevelopment ? deviceRequireSecureConfig : true,
                        SameSite = deviceSameSite,
                        Path = "/",
                        MaxAge = refreshExpires - DateTime.UtcNow
                    });

                rememberIssued = true;
            }

            return Results.Ok(new { ok = true, csrfToken, rememberIssued, deviceIssued, deviceId, refreshExpiresAtUtc = refreshExpiresUtc, idToken, refreshCsrfToken });
        });
    }

}
