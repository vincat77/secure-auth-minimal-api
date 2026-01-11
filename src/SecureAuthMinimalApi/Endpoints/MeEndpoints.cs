using System.Text.Json;
using Microsoft.Extensions.Logging;
using SecureAuthMinimalApi.Utilities;
using SecureAuthMinimalApi.Logging;
namespace SecureAuthMinimalApi.Endpoints;

public static class MeEndpoints
{
    /// <summary>
    /// Mappa l'endpoint /me che restituisce i dati della sessione corrente.
    /// </summary>
    public static void MapMe(this WebApplication app)
    {
        app.MapGet("/me", (HttpContext ctx, ILogger<MeLogger> logger) =>
        {
            var session = ctx.GetRequiredSession();
            logger.LogInformation("Recupero /me sessionId={SessionId} userId={UserId}", session.SessionId, session.UserId);
            return Results.Ok(new
            {
                ok = true,
                sessionId = session.SessionId,
                userId = session.UserId,
                createdAtUtc = session.CreatedAtUtc,
                expiresAtUtc = session.ExpiresAtUtc,
                userData = JsonSerializer.Deserialize<JsonElement>(session.UserDataJson)
            });
        });
    }
}
