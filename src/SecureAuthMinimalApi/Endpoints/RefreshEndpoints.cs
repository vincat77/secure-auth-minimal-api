using System.Text.Json;
using Microsoft.Extensions.Logging;
using SecureAuthMinimalApi.Data;
using SecureAuthMinimalApi.Models;
using SecureAuthMinimalApi.Services;
using static SecureAuthMinimalApi.Endpoints.EndpointUtilities;

namespace SecureAuthMinimalApi.Endpoints;

public static class RefreshEndpoints
{
    public static void MapRefresh(this WebApplication app, ILogger logger)
    {
        var isDevelopment = app.Environment.IsDevelopment();

        app.MapPost("/refresh", async (HttpContext ctx, JwtTokenService jwt, RefreshTokenRepository refreshRepo, SessionRepository sessions, UserRepository users) =>
        {
            var cookieName = app.Configuration["RememberMe:CookieName"] ?? "refresh_token";
            var deviceCookieName = app.Configuration["Device:CookieName"] ?? "device_id";
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
            if (!string.Equals(ua, stored.UserAgent, StringComparison.Ordinal))
                return Results.Unauthorized();

            var user = await users.GetByIdAsync(stored.UserId, ctx.RequestAborted);
            if (user is null)
                return Results.Unauthorized();

            var sessionId = Guid.NewGuid().ToString("N");
            var csrfToken = Base64Url(RandomBytes(32));
            var (access, expiresUtc) = jwt.CreateAccessToken(sessionId);
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
                CsrfToken = csrfToken,
                LastSeenUtc = nowIso
            };
            await sessions.CreateAsync(session, ctx.RequestAborted);

            var rememberConfigDays = app.Configuration.GetValue<int?>("RememberMe:Days") ?? 14;
            var rememberSameSiteString = app.Configuration["RememberMe:SameSite"] ?? "Strict";
            var rememberSameSite = SameSiteMode.Strict;
            if (rememberSameSiteString.Equals("Lax", StringComparison.OrdinalIgnoreCase))
                rememberSameSite = SameSiteMode.Lax;
            var rememberPath = app.Configuration["RememberMe:Path"] ?? "/refresh";
            var requireSecure = isDevelopment ? app.Configuration.GetValue<bool>("Cookie:RequireSecure") : true;
            var deviceSameSiteString = app.Configuration["Device:SameSite"] ?? "Strict";
            var deviceSameSite = SameSiteMode.Strict;
            if (deviceSameSiteString.Equals("Lax", StringComparison.OrdinalIgnoreCase))
                deviceSameSite = SameSiteMode.Lax;
            else if (deviceSameSiteString.Equals("None", StringComparison.OrdinalIgnoreCase))
                deviceSameSite = SameSiteMode.None;
            var deviceRequireSecureConfig = app.Configuration.GetValue<bool?>("Device:RequireSecure");
            var deviceRequireSecure = isDevelopment
                ? (deviceRequireSecureConfig ?? (app.Configuration.GetValue<bool?>("Cookie:RequireSecure") ?? false))
                : true;
            var devicePersistDays = app.Configuration.GetValue<int?>("Device:PersistDays") ?? rememberConfigDays;

            var newRefreshToken = Base64Url(RandomBytes(32));
            var refreshExpires = DateTime.UtcNow.AddDays(rememberConfigDays);
            var newRt = new RefreshToken
            {
                Id = Guid.NewGuid().ToString("N"),
                UserId = user.Id,
                SessionId = sessionId,
                Token = newRefreshToken,
                TokenHash = null,
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

            return Results.Ok(new { ok = true, csrfToken, rememberIssued = true, deviceIssued = false, deviceId = newRt.DeviceId, refreshExpiresAtUtc = refreshExpires.ToString("O") });
        });
    }
}
