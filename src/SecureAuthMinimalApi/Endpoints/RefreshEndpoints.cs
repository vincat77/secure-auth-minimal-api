using System.Text.Json;
using Microsoft.Extensions.Logging;
using SecureAuthMinimalApi.Data;
using SecureAuthMinimalApi.Models;
using SecureAuthMinimalApi.Options;
using SecureAuthMinimalApi.Services;
using static SecureAuthMinimalApi.Endpoints.EndpointUtilities;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;

namespace SecureAuthMinimalApi.Endpoints;

public static class RefreshEndpoints
{
    /// <summary>
    /// Mappa l'endpoint di refresh che ruota il token di refresh e rilascia nuova sessione/access token.
    /// </summary>
    public static void MapRefresh(this WebApplication app, ILogger logger)
    {
        var isDevelopment = app.Environment.IsDevelopment();
        var refreshOptions = app.Services.GetRequiredService<IOptions<RefreshOptions>>().Value;
        var rememberOptions = app.Services.GetRequiredService<IOptions<RememberMeOptions>>().Value;
        var deviceOptions = app.Services.GetRequiredService<IOptions<DeviceOptions>>().Value;
        var cookieConfig = app.Services.GetRequiredService<IOptions<CookieConfigOptions>>().Value;

        app.MapPost("/refresh", async (HttpContext ctx, JwtTokenService jwt, RefreshTokenRepository refreshRepo, SessionRepository sessions, UserRepository users) =>
        {
            var cookieName = refreshOptions.CookieName ?? rememberOptions.CookieName ?? "refresh_token";
            var deviceCookieName = deviceOptions.CookieName ?? "device_id";
            if (!ctx.Request.Cookies.TryGetValue(cookieName, out var refreshToken) || string.IsNullOrWhiteSpace(refreshToken))
                return Results.Unauthorized();

            var stored = await refreshRepo.GetByTokenAsync(refreshToken, ctx.RequestAborted);
            if (stored is null || !string.IsNullOrWhiteSpace(stored.RevokedAtUtc))
                return Results.Unauthorized();

            if (!ctx.Request.Cookies.TryGetValue(deviceCookieName, out var cookieDeviceId) || string.IsNullOrWhiteSpace(cookieDeviceId))
            {
                logger.LogWarning("Refresh negato: device cookie assente");
                return Results.Unauthorized();
            }

            if (!string.Equals(cookieDeviceId, stored.DeviceId, StringComparison.Ordinal))
            {
                logger.LogWarning("Refresh negato: device mismatch stored={Stored} cookie={Cookie}", stored.DeviceId, cookieDeviceId);
                return Results.Unauthorized();
            }

            if (!DateTime.TryParse(stored.ExpiresAtUtc, out var expRt) || expRt.ToUniversalTime() <= DateTime.UtcNow)
                return Results.Unauthorized();

            var ua = ctx.Request.Headers["User-Agent"].ToString();
            if (refreshOptions.RequireUserAgentMatch && !string.Equals(ua, stored.UserAgent, StringComparison.Ordinal))
                return Results.Unauthorized();

            // CSRF refresh token: header obbligatorio
            if (!ctx.Request.Headers.TryGetValue("X-Refresh-Csrf", out var refreshCsrf) || string.IsNullOrWhiteSpace(refreshCsrf))
                return Results.StatusCode(StatusCodes.Status403Forbidden);
            if (string.IsNullOrWhiteSpace(stored.RefreshCsrfHash) || !SecurityUtils.FixedTimeEquals(HashToken(refreshCsrf!), stored.RefreshCsrfHash))
                return Results.StatusCode(StatusCodes.Status403Forbidden);

            var user = await users.GetByIdAsync(stored.UserId, ctx.RequestAborted);
            if (user is null)
                return Results.Unauthorized();

            var sessionId = Guid.NewGuid().ToString("N");
            var csrfToken = Base64Url(RandomBytes(32));
            var (access, expiresUtc) = jwt.CreateAccessToken(sessionId);
            var nowIso = DateTime.UtcNow.ToString("O");
            var expIso = expiresUtc.ToString("O");
            var refreshCsrfToken = Base64Url(RandomBytes(32));
            var refreshCsrfHash = HashToken(refreshCsrfToken);

            var session = new UserSession
            {
                SessionId = sessionId,
                UserId = user.Id,
                CreatedAtUtc = nowIso,
                ExpiresAtUtc = expIso,
                RevokedAtUtc = null,
                UserDataJson = JsonSerializer.Serialize(new { username = user.Username }),
                CsrfToken = csrfToken,
                LastSeenUtc = nowIso
            };
            await sessions.CreateAsync(session, ctx.RequestAborted);

            var rememberConfigDays = rememberOptions.Days <= 0 ? 14 : rememberOptions.Days;
            var refreshSameSiteValue = string.IsNullOrWhiteSpace(refreshOptions.SameSite) ? rememberOptions.SameSite : refreshOptions.SameSite;
            var rememberSameSite = ParseSameSite(refreshSameSiteValue, refreshOptions.AllowSameSiteNone || rememberOptions.AllowSameSiteNone, isDevelopment, logger, "Refresh");
            var rememberPath = refreshOptions.Path ?? rememberOptions.Path ?? "/refresh";
            var requireSecureConfig = refreshOptions.RequireSecure || cookieConfig.RequireSecure;
            var requireSecure = isDevelopment ? requireSecureConfig : true;
            if (!isDevelopment && !requireSecureConfig)
            {
                logger.LogWarning("Refresh:RequireSecure=false in ambiente non Development: forzato a true");
            }

            var deviceSameSite = ParseSameSite(deviceOptions.SameSite, deviceOptions.AllowSameSiteNone, isDevelopment, logger, "Device");
            var deviceRequireSecureConfig = deviceOptions.RequireSecure || cookieConfig.RequireSecure;
            var deviceRequireSecure = isDevelopment ? deviceRequireSecureConfig : true;
            if (!isDevelopment && !deviceRequireSecureConfig)
            {
                logger.LogWarning("Device:RequireSecure=false in ambiente non Development: forzato a true");
            }
            var devicePersistDays = deviceOptions.PersistDays <= 0 ? rememberConfigDays : deviceOptions.PersistDays;

            var newRefreshToken = Base64Url(RandomBytes(32));
            var refreshExpires = DateTime.UtcNow.AddDays(rememberConfigDays);
            var newRt = new RefreshToken
            {
                Id = Guid.NewGuid().ToString("N"),
                UserId = user.Id,
                SessionId = sessionId,
                Token = newRefreshToken,
                TokenHash = null,
                RefreshCsrfHash = refreshCsrfHash,
                CreatedAtUtc = nowIso,
                ExpiresAtUtc = refreshExpires.ToString("O"),
                RevokedAtUtc = null,
                UserAgent = ua,
                ClientIp = ctx.Connection.RemoteIpAddress?.ToString(),
                DeviceId = stored.DeviceId,
                DeviceLabel = stored.DeviceLabel,
                RotationParentId = stored.Id,
                RotationReason = "rotated"
            };

            await refreshRepo.RotateAsync(stored.Id, newRt, "rotated", ctx.RequestAborted);

            ctx.Response.Cookies.Append(
                "access_token",
                access,
                new CookieOptions
                {
                    HttpOnly = true,
                    Secure = requireSecure,
                    SameSite = SameSiteMode.Strict,
                    Path = "/",
                    MaxAge = expiresUtc - DateTime.UtcNow
                });

            ctx.Response.Cookies.Append(
                cookieName,
                newRefreshToken,
                new CookieOptions
                {
                    HttpOnly = true,
                    Secure = requireSecure,
                    SameSite = rememberSameSite,
                    Path = rememberPath,
                    MaxAge = refreshExpires - DateTime.UtcNow
                });

            if (!string.IsNullOrWhiteSpace(newRt.DeviceId))
            {
                ctx.Response.Cookies.Append(
                    deviceCookieName,
                    newRt.DeviceId,
                    new CookieOptions
                    {
                        HttpOnly = true,
                        Secure = deviceRequireSecure,
                        SameSite = deviceSameSite,
                        Path = "/",
                        MaxAge = TimeSpan.FromDays(devicePersistDays)
                    });
            }

            return Results.Ok(new { ok = true, csrfToken, rememberIssued = true, deviceIssued = false, deviceId = newRt.DeviceId, refreshExpiresAtUtc = refreshExpires.ToString("O"), refreshCsrfToken });
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
