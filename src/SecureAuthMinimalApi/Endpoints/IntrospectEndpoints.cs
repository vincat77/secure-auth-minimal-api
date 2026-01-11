using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using SecureAuthMinimalApi.Data;
using SecureAuthMinimalApi.Services;
using SecureAuthMinimalApi.Utilities;
using SecureAuthMinimalApi.Logging;

namespace SecureAuthMinimalApi.Endpoints;

public static class IntrospectEndpoints
{
    /// <summary>
    /// Mappa l'endpoint di introspezione che restituisce lo stato della sessione associata al token.
    /// </summary>
    public static void MapIntrospect(this WebApplication app)
    {
        app.MapGet("/introspect", async (HttpContext ctx, JwtTokenService jwt, SessionRepository sessions, ILogger<IntrospectLogger> logger) =>
        {
            if (!AuthHelpers.TryGetToken(ctx, out var token))
                return Results.Unauthorized();

            var handler = new JwtSecurityTokenHandler { MapInboundClaims = false };
            JwtSecurityToken? parsed = null;
            try
            {
                handler.ValidateToken(token, jwt.GetValidationParameters(), out var validated);
                parsed = validated as JwtSecurityToken;
            }
            catch (SecurityTokenException)
            {
                logger.LogWarning("Introspect: token non valido");
                return Results.Ok(new { active = false, reason = "invalid_token" });
            }
            catch (ArgumentException)
            {
                logger.LogWarning("Introspect: token non valido (arg)");
                return Results.Ok(new { active = false, reason = "invalid_token" });
            }

            var sessionId = parsed?.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Sub)?.Value;
            if (string.IsNullOrWhiteSpace(sessionId))
                return Results.Ok(new { active = false, reason = "invalid_token" });

            var session = await sessions.GetByIdAsync(sessionId, ctx.RequestAborted);
            if (session is null)
            {
                logger.LogWarning("Introspect: sessione non trovata");
                return Results.Ok(new { active = false, reason = "not_found" });
            }

            if (!string.IsNullOrWhiteSpace(session.RevokedAtUtc))
            {
                logger.LogInformation("Introspect: sessione revocata sessionId={SessionId}", session.SessionId);
                return Results.Ok(new { active = false, reason = "revoked" });
            }

            var exp = DateTime.Parse(session.ExpiresAtUtc).ToUniversalTime();
            if (exp <= DateTime.UtcNow)
            {
                logger.LogInformation("Introspect: sessione scaduta sessionId={SessionId} userId={UserId} exp={Exp}", session.SessionId, session.UserId, session.ExpiresAtUtc);
                return Results.Ok(new { active = false, reason = "expired" });
            }

            logger.LogInformation("Introspect: sessione attiva sessionId={SessionId} userId={UserId} exp={Exp} iss={Iss} aud={Aud}", session.SessionId, session.UserId, session.ExpiresAtUtc, parsed?.Issuer, string.Join(",", parsed?.Audiences ?? Enumerable.Empty<string>()));
            return Results.Ok(new
            {
                active = true,
                sessionId = session.SessionId,
                userId = session.UserId,
                expiresAtUtc = session.ExpiresAtUtc
            });
        });
    }
}
