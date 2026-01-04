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
        app.MapGet("/live", () => Results.Ok(new { ok = true }));
    }
}
