using System.Text.Json;
using Microsoft.Extensions.Logging;
using SecureAuthMinimalApi.Data;
using SecureAuthMinimalApi.Models;
using SecureAuthMinimalApi.Services;
using static SecureAuthMinimalApi.Endpoints.EndpointUtilities;

namespace SecureAuthMinimalApi.Endpoints;

public static class ConfirmMfaEndpoints
{
    public static void MapConfirmMfa(
        this WebApplication app,
        ILogger logger,
        bool mfaRequireUaMatch,
        bool mfaRequireIpMatch,
        int mfaMaxAttempts)
    {
        var isDevelopment = app.Environment.IsDevelopment();

        app.MapPost("/login/confirm-mfa", async (HttpContext ctx, JwtTokenService jwt, IdTokenService idTokenService, SessionRepository sessions, UserRepository users, MfaChallengeRepository challenges, LoginAuditRepository auditRepo) =>
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
            if (mfaRequireUaMatch && !string.Equals(ua, challenge.UserAgent, StringComparison.Ordinal))
            {
                logger.LogWarning("Confirm MFA: UA mismatch atteso={Expected} actual={Actual}", challenge.UserAgent, ua);
                return Results.Unauthorized();
            }

            if (mfaRequireIpMatch)
            {
                var reqIp = ctx.Request.Headers["X-Forwarded-For"].FirstOrDefault() ?? ctx.Connection.RemoteIpAddress?.ToString();
                if (!string.Equals(reqIp, challenge.ClientIp, StringComparison.Ordinal))
                {
                    logger.LogWarning("Confirm MFA: IP mismatch atteso={Expected} actual={Actual}", challenge.ClientIp, reqIp);
                    return Results.Unauthorized();
                }
            }

            if (challenge.AttemptCount >= mfaMaxAttempts)
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
                logger.LogWarning("Confirm MFA: TOTP errato challengeId={ChallengeId} code={Code}", challenge.Id, body.TotpCode);
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

            var rememberIssued = false;
            string? refreshExpiresUtc = null;
            var deviceIssued = false;
            string? deviceId = null;

            if (body.RememberMe)
            {
                var rememberConfigDays = app.Configuration.GetValue<int?>("RememberMe:Days") ?? 14;
                var rememberSameSiteString = app.Configuration["RememberMe:SameSite"] ?? "Strict";
                var rememberSameSite = SameSiteMode.Strict;
                if (rememberSameSiteString.Equals("Lax", StringComparison.OrdinalIgnoreCase))
                    rememberSameSite = SameSiteMode.Lax;
                var rememberPath = app.Configuration["RememberMe:Path"] ?? "/refresh";
                var refreshToken = Base64Url(RandomBytes(32));
                var refreshExpires = DateTime.UtcNow.AddDays(rememberConfigDays);
                var refreshRepo = ctx.RequestServices.GetRequiredService<RefreshTokenRepository>();

                var deviceCookieName = app.Configuration["Device:CookieName"] ?? "device_id";
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

                var rememberCookieName = app.Configuration["RememberMe:CookieName"] ?? "refresh_token";
                var rememberSecure = isDevelopment ? requireSecureConfig : true;
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

                var deviceSameSiteString = app.Configuration["Device:SameSite"] ?? "Strict";
                var deviceSameSite = SameSiteMode.Strict;
                if (deviceSameSiteString.Equals("Lax", StringComparison.OrdinalIgnoreCase))
                    deviceSameSite = SameSiteMode.Lax;
                ctx.Response.Cookies.Append(
                    deviceCookieName,
                    deviceId!,
                    new CookieOptions
                    {
                        HttpOnly = true,
                        Secure = app.Configuration.GetValue<bool?>("Device:RequireSecure") ?? requireSecure,
                        SameSite = deviceSameSite,
                        Path = "/",
                        MaxAge = refreshExpires - DateTime.UtcNow
                    });

                rememberIssued = true;
            }

            return Results.Ok(new { ok = true, csrfToken, rememberIssued, deviceIssued, deviceId, refreshExpiresAtUtc = refreshExpiresUtc, idToken });
        });
    }
}
