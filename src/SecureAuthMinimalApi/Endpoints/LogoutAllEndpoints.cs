using Microsoft.Extensions.Logging;
using SecureAuthMinimalApi.Data;
using SecureAuthMinimalApi.Options;
using SecureAuthMinimalApi.Filters;

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

            var rememberOptions = ctx.RequestServices.GetRequiredService<Microsoft.Extensions.Options.IOptions<RememberMeOptions>>().Value;
            var deviceOptions = ctx.RequestServices.GetRequiredService<Microsoft.Extensions.Options.IOptions<DeviceOptions>>().Value;

            var requireSecure = isDevelopment ? rememberOptions.RequireSecure : true;
            ctx.Response.Cookies.Append("access_token", "", new CookieOptions
            {
                Expires = DateTimeOffset.UnixEpoch,
                HttpOnly = true,
                Secure = requireSecure,
                SameSite = SameSiteMode.Strict,
                Path = "/"
            });
            ctx.Response.Cookies.Append(rememberOptions.CookieName ?? "refresh_token", "", new CookieOptions
            {
                Expires = DateTimeOffset.UnixEpoch,
                HttpOnly = true,
                Secure = requireSecure,
                SameSite = SameSiteMode.Strict,
                Path = rememberOptions.Path ?? "/refresh"
            });
            var clearDevice = deviceOptions.ClearOnLogoutAll;
            if (clearDevice)
            {
                var deviceCookieName = deviceOptions.CookieName ?? "device_id";
                var deviceSameSite = SameSiteMode.Strict;
                if ((deviceOptions.SameSite ?? "Strict").Equals("Lax", StringComparison.OrdinalIgnoreCase))
                    deviceSameSite = SameSiteMode.Lax;
                else if ((deviceOptions.SameSite ?? "Strict").Equals("None", StringComparison.OrdinalIgnoreCase))
                    deviceSameSite = SameSiteMode.None;
                var deviceRequireSecure = isDevelopment ? deviceOptions.RequireSecure : true;

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
        })
        .RequireSession()
        .RequireCsrf();
    }
}
