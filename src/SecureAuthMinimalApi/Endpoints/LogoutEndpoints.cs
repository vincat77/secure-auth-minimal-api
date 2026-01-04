using Microsoft.Extensions.Logging;
using SecureAuthMinimalApi.Data;

namespace SecureAuthMinimalApi.Endpoints;

public static class LogoutEndpoints
{
    /// <summary>
    /// Mappa l'endpoint di logout che revoca la sessione corrente e pulisce i cookie.
    /// </summary>
    public static void MapLogout(this WebApplication app, ILogger logger)
    {
        var isDevelopment = app.Environment.IsDevelopment();

        app.MapPost("/logout", async (HttpContext ctx, SessionRepository sessions) =>
        {
            var session = ctx.GetRequiredSession();

            await sessions.RevokeAsync(session.SessionId, DateTime.UtcNow.ToString("O"), ctx.RequestAborted);
            logger.LogInformation("Logout OK sessionId={SessionId} userId={UserId} revokedAt={RevokedAt}", session.SessionId, session.UserId, DateTime.UtcNow.ToString("O"));

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
        });
    }
}
