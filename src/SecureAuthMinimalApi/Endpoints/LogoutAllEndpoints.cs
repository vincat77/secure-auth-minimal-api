using Microsoft.Extensions.Logging;
using SecureAuthMinimalApi.Data;

namespace SecureAuthMinimalApi.Endpoints;

public static class LogoutAllEndpoints
{
    /// <summary>
    /// Mappa l'endpoint di logout globale che revoca refresh e sessione corrente.
    /// </summary>
    public static void MapLogoutAll(this WebApplication app, ILogger logger)
    {
        var isDevelopment = app.Environment.IsDevelopment();

        app.MapPost("/logout-all", async (HttpContext ctx, SessionRepository sessions, RefreshTokenRepository refreshRepo) =>
        {
            var session = ctx.GetRequiredSession();

            await refreshRepo.RevokeAllForUserAsync(session.UserId, "logout-all", ctx.RequestAborted);
            await sessions.RevokeAsync(session.SessionId, DateTime.UtcNow.ToString("O"), ctx.RequestAborted);
            logger.LogInformation("Logout-all eseguito userId={UserId} sessionId={SessionId}", session.UserId, session.SessionId);

            var requireSecure = isDevelopment ? app.Configuration.GetValue<bool>("Cookie:RequireSecure") : true;
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
            var clearDevice = app.Configuration.GetValue<bool?>("Device:ClearOnLogoutAll") ?? false;
            if (clearDevice)
            {
                var deviceCookieName = app.Configuration["Device:CookieName"] ?? "device_id";
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

                ctx.Response.Cookies.Append(deviceCookieName, "", new CookieOptions
                {
                    Expires = DateTimeOffset.UnixEpoch,
                    HttpOnly = true,
                    Secure = deviceRequireSecure,
                    SameSite = deviceSameSite,
                    Path = "/"
                });
            }

            return Results.Ok(new { ok = true });
        });
    }
}
