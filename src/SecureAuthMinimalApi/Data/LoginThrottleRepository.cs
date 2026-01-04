using System.Data;
using Dapper;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;

namespace SecureAuthMinimalApi.Data;

/// <summary>
/// Persistenza throttling login su DB (SQLite).
/// </summary>
public sealed class LoginThrottleRepository
{
    private readonly string _connectionString;

    public LoginThrottleRepository(IConfiguration config)
    {
        _connectionString = config.GetConnectionString("Sqlite")
            ?? throw new InvalidOperationException("Missing ConnectionStrings:Sqlite in appsettings.json");
    }

    private IDbConnection Open() => new SqliteConnection(_connectionString);

    public async Task<ThrottleState> GetAsync(string username, CancellationToken ct)
    {
        const string sql = @"
SELECT username AS Username, failures AS Failures, locked_until_utc AS LockedUntilUtc
FROM login_throttle
WHERE username = @username;";

        using var db = Open();
        var row = await db.QuerySingleOrDefaultAsync<ThrottleRow>(new CommandDefinition(sql, new { username }, cancellationToken: ct));
        if (row is null)
            return new ThrottleState(username, 0, DateTimeOffset.MinValue);

        var locked = DateTimeOffset.Parse(row.LockedUntilUtc).ToUniversalTime();
        return new ThrottleState(username, row.Failures, locked);
    }

    public async Task SaveAsync(ThrottleState state, CancellationToken ct)
    {
        const string sql = @"
INSERT INTO login_throttle (username, failures, locked_until_utc)
VALUES (@Username, @Failures, @LockedUntilUtc)
ON CONFLICT(username) DO UPDATE SET
  failures = excluded.failures,
  locked_until_utc = excluded.locked_until_utc;";

        using var db = Open();
        await db.ExecuteAsync(new CommandDefinition(sql, new
        {
            state.Username,
            state.Failures,
            LockedUntilUtc = state.LockedUntilUtc.ToString("O")
        }, cancellationToken: ct));
    }

    public async Task ResetAsync(string username, CancellationToken ct)
    {
        const string sql = "DELETE FROM login_throttle WHERE username = @username;";
        using var db = Open();
        await db.ExecuteAsync(new CommandDefinition(sql, new { username }, cancellationToken: ct));
    }

    /// <summary>
    /// DTO interno per mappare la riga SQLite del throttling.
    /// </summary>
    private sealed record ThrottleRow
    {
        public string Username { get; init; } = "";
        public int Failures { get; init; }
        public string LockedUntilUtc { get; init; } = "";
    }
}

/// <summary>
/// Stato del throttling corrente per uno username.
/// </summary>
public sealed record ThrottleState(string Username, int Failures, DateTimeOffset LockedUntilUtc);
