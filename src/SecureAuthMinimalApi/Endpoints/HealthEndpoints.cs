using Microsoft.Extensions.Logging;
using SecureAuthMinimalApi.Logging;

namespace SecureAuthMinimalApi.Endpoints;

/// <summary>
/// Endpoint di health check per verificare disponibilità dell'applicazione.
/// </summary>
public static class HealthEndpoints
{
    /// <summary>
    /// Mappa l'endpoint di health (/health) che ritorna ok=true.
    /// </summary>
    public static void MapHealth(this WebApplication app)
    {
        app.MapGet("/health", (ILogger<HealthLogger> logger) =>
        {
            logger.LogInformation("Health check OK");
            return Results.Ok(new { ok = true });
        });
    }
}
