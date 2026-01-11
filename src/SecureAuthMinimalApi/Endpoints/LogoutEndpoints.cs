using SecureAuthMinimalApi.Data;
using SecureAuthMinimalApi.Options;
using SecureAuthMinimalApi.Filters;
using SecureAuthMinimalApi.Utilities;
namespace SecureAuthMinimalApi.Endpoints;

public static class LogoutEndpoints
{
    /// <summary>
    /// Mappa l'endpoint di logout che revoca la sessione corrente e pulisce i cookie.
    /// </summary>
    public static void MapLogout(this WebApplication app)
    {
        var isDevelopment = app.Environment.IsDevelopment();

        app.MapPost("/logout", async (HttpContext ctx, SessionRepository sessions, ILogger logger) =>
        {
            var session = ctx.GetRequiredSession();

            await sessions.RevokeAsync(session.SessionId, DateTime.UtcNow.ToString("O"), ctx.RequestAborted);
            logger.LogInformation("Logout OK sessionId={SessionId} userId={UserId} revokedAt={RevokedAt}", session.SessionId, session.UserId, DateTime.UtcNow.ToString("O"));

            var rememberOptions = ctx.RequestServices.GetRequiredService<Microsoft.Extensions.Options.IOptions<RememberMeOptions>>().Value;
            var deviceOptions = ctx.RequestServices.GetRequiredService<Microsoft.Extensions.Options.IOptions<DeviceOptions>>().Value;
            var cookieConfig = ctx.RequestServices.GetRequiredService<Microsoft.Extensions.Options.IOptions<CookieConfigOptions>>().Value;

            var requireSecure = isDevelopment ? rememberOptions.RequireSecure : cookieConfig.RequireSecure || rememberOptions.RequireSecure;
            ctx.Response.Cookies.Append("access_token", "", new CookieOptions
            {
                Expires = DateTimeOffset.UnixEpoch,
                HttpOnly = true,
                Secure = requireSecure,
                SameSite = SameSiteMode.Strict,
                Path = "/"
            });

            if (ctx.Request.Cookies.TryGetValue(rememberOptions.CookieName ?? "refresh_token", out var refreshToken) && !string.IsNullOrWhiteSpace(refreshToken))
            {
                var refreshRepo = ctx.RequestServices.GetRequiredService<RefreshTokenRepository>();
                await refreshRepo.RevokeByTokenAsync(refreshToken, "logout", ctx.RequestAborted);
                ctx.Response.Cookies.Append(rememberOptions.CookieName ?? "refresh_token", "", new CookieOptions
                {
                    Expires = DateTimeOffset.UnixEpoch,
                    HttpOnly = true,
                    Secure = requireSecure,
                    SameSite = SameSiteMode.Strict,
                    Path = rememberOptions.Path ?? "/refresh"
                });
                logger.LogInformation("Logout: refresh token revocato");
            }

            // Pulisce device cookie
            ctx.Response.Cookies.Append(deviceOptions.CookieName ?? "device_id", "", new CookieOptions
            {
                Expires = DateTimeOffset.UnixEpoch,
                HttpOnly = true,
                Secure = isDevelopment ? deviceOptions.RequireSecure : true,
                SameSite = SameSiteMode.Strict,
                Path = "/"
            });

            return Results.Ok(new { ok = true });
        })
        .RequireSession()
        .RequireCsrf();
    }
}
