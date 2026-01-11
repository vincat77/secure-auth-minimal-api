using Microsoft.Extensions.Logging;
using SecureAuthMinimalApi.Logging;

namespace SecureAuthMinimalApi.Endpoints;

/// <summary>
/// Endpoint di liveness semplice per indicare che il processo è attivo.
/// </summary>
public static class LiveEndpoints
{
    /// <summary>
    /// Mappa l'endpoint /live che restituisce ok=true.
    /// </summary>
    public static void MapLive(this WebApplication app)
    {
        app.MapGet("/live", (ILogger<LiveLogger> logger) =>
        {
            logger.LogInformation("Live check OK");
            return Results.Ok(new { ok = true });
        });
    }
}
