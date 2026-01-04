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
        app.MapGet("/health", () => Results.Ok(new { ok = true }));
    }
}
