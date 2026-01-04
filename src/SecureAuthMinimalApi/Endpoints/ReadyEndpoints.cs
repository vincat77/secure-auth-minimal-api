using Microsoft.Data.Sqlite;

namespace SecureAuthMinimalApi.Endpoints;

public static class ReadyEndpoints
{
    /// <summary>
    /// Mappa l'endpoint /ready che verifica configurazione JWT e raggiungibilità del database.
    /// </summary>
    public static void MapReady(this WebApplication app)
    {
        app.MapGet("/ready", async (IConfiguration config) =>
        {
            try
            {
                var connString = config.GetConnectionString("Sqlite");
                if (string.IsNullOrWhiteSpace(connString))
                    return Results.Json(new { ok = false, error = "db_config_missing" }, statusCode: StatusCodes.Status503ServiceUnavailable);

                var iss = config["Jwt:Issuer"];
                var aud = config["Jwt:Audience"];
                var secret = config["Jwt:SecretKey"];
                if (string.IsNullOrWhiteSpace(iss) || string.IsNullOrWhiteSpace(aud) || string.IsNullOrWhiteSpace(secret) || secret.Trim().Length < 32)
                    return Results.Json(new { ok = false, error = "invalid_config" }, statusCode: StatusCodes.Status503ServiceUnavailable);

                await using var conn = new SqliteConnection(connString);
                await conn.OpenAsync();
                var cmd = conn.CreateCommand();
                cmd.CommandText = "SELECT 1;";
                cmd.CommandTimeout = 3;
                await cmd.ExecuteScalarAsync();

                return Results.Ok(new { ok = true });
            }
            catch
            {
                return Results.Json(new { ok = false, error = "db_unreachable" }, statusCode: StatusCodes.Status503ServiceUnavailable);
            }
        });
    }
}
