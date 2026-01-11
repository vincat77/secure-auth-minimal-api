using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;
using SecureAuthMinimalApi.Logging;
using SecureAuthMinimalApi.Options;

namespace SecureAuthMinimalApi.Endpoints;

public static class ReadyEndpoints
{
    /// <summary>
    /// Mappa l'endpoint /ready che verifica configurazione JWT e raggiungibilità del database.
    /// </summary>
    public static void MapReady(this WebApplication app)
    {
        app.MapGet("/ready", async (IOptions<ConnectionStringsOptions> connOpts, IOptions<JwtOptions> jwtOpts, ILogger<ReadyLogger> logger) =>
        {
            try
            {
                var connString = connOpts.Value.Sqlite;
                if (string.IsNullOrWhiteSpace(connString))
                    return Results.Json(new { ok = false, error = "db_config_missing" }, statusCode: StatusCodes.Status503ServiceUnavailable);

                var iss = jwtOpts.Value.Issuer;
                var aud = jwtOpts.Value.Audience;
                var secret = jwtOpts.Value.SecretKey;
                if (string.IsNullOrWhiteSpace(iss) || string.IsNullOrWhiteSpace(aud) || string.IsNullOrWhiteSpace(secret) || secret.Trim().Length < 32)
                    return Results.Json(new { ok = false, error = "invalid_config" }, statusCode: StatusCodes.Status503ServiceUnavailable);

                await using var conn = new SqliteConnection(connString);
                await conn.OpenAsync();
                var cmd = conn.CreateCommand();
                cmd.CommandText = "SELECT 1;";
                cmd.CommandTimeout = 3;
                await cmd.ExecuteScalarAsync();

                logger.LogInformation("Ready check OK");
                return Results.Ok(new { ok = true });
            }
            catch
            {
                logger.LogWarning("Ready check fallito");
                return Results.Json(new { ok = false, error = "db_unreachable" }, statusCode: StatusCodes.Status503ServiceUnavailable);
            }
        });
    }
}
