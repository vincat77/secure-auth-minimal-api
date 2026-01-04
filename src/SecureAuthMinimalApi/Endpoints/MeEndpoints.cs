using System.Text.Json;

namespace SecureAuthMinimalApi.Endpoints;

public static class MeEndpoints
{
    /// <summary>
    /// Mappa l'endpoint /me che restituisce i dati della sessione corrente.
    /// </summary>
    public static void MapMe(this WebApplication app)
    {
        app.MapGet("/me", (HttpContext ctx) =>
        {
            var session = ctx.GetRequiredSession();
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
