using System.Data;
using Dapper;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using SecureAuthMinimalApi.Models;

namespace SecureAuthMinimalApi.Data;

/// <summary>
/// Persistenza eventi di audit login.
/// </summary>
public sealed class LoginAuditRepository
{
    private readonly string _connectionString;

    /// <summary>
    /// Recupera connection string per il repository audit.
    /// </summary>
    public LoginAuditRepository(IConfiguration config)
    {
        _connectionString = config.GetConnectionString("Sqlite")
            ?? throw new InvalidOperationException("Missing ConnectionStrings:Sqlite in appsettings.json");
    }

    private IDbConnection Open() => new SqliteConnection(_connectionString);

    /// <summary>
    /// Inserisce un evento di audit nel DB.
    /// </summary>
    public async Task CreateAsync(LoginAudit audit, CancellationToken ct)
    {
        const string sql = @"
INSERT INTO login_audit (id, username, outcome, timestamp_utc, client_ip, user_agent, detail)
VALUES (@Id, @Username, @Outcome, @TimestampUtc, @ClientIp, @UserAgent, @Detail);";

        using var db = Open();
        await db.ExecuteAsync(new CommandDefinition(sql, audit, cancellationToken: ct));
    }
}
