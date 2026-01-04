namespace SecureAuthMinimalApi.Endpoints;

public static class LiveEndpoints
{
    public static void MapLive(this WebApplication app)
    {
        app.MapGet("/live", () => Results.Ok(new { ok = true }));
    }
}
