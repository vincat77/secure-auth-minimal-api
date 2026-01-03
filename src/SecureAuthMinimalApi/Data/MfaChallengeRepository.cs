using System.Data;
using Dapper;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using SecureAuthMinimalApi.Models;

namespace SecureAuthMinimalApi.Data;

/// <summary>
/// Gestione dei challenge MFA (creazione e lettura).
/// </summary>
public sealed class MfaChallengeRepository
{
    private readonly string _connectionString;

    public MfaChallengeRepository(IConfiguration config)
    {
        _connectionString = config.GetConnectionString("Sqlite")
            ?? throw new InvalidOperationException("Missing ConnectionStrings:Sqlite in appsettings.json");
    }

    private IDbConnection Open() => new SqliteConnection(_connectionString);

    public async Task CreateAsync(MfaChallenge challenge, CancellationToken ct)
    {
        const string sql = @"
INSERT INTO mfa_challenges (id, user_id, created_at_utc, expires_at_utc, used_at_utc, user_agent, client_ip, attempt_count)
VALUES (@Id, @UserId, @CreatedAtUtc, @ExpiresAtUtc, @UsedAtUtc, @UserAgent, @ClientIp, @AttemptCount);";

        using var db = Open();
        await db.ExecuteAsync(new CommandDefinition(sql, new
        {
            challenge.Id,
            challenge.UserId,
            challenge.CreatedAtUtc,
            challenge.ExpiresAtUtc,
            challenge.UsedAtUtc,
            challenge.UserAgent,
            challenge.ClientIp,
            challenge.AttemptCount
        }, cancellationToken: ct));
    }

    public async Task<MfaChallenge?> GetByIdAsync(string id, CancellationToken ct)
    {
        const string sql = @"
SELECT id AS Id, user_id AS UserId, created_at_utc AS CreatedAtUtc, expires_at_utc AS ExpiresAtUtc,
       used_at_utc AS UsedAtUtc, user_agent AS UserAgent, client_ip AS ClientIp, attempt_count AS AttemptCount
FROM mfa_challenges
WHERE id = @id
LIMIT 1;";

        using var db = Open();
        return await db.QuerySingleOrDefaultAsync<MfaChallenge>(new CommandDefinition(sql, new { id }, cancellationToken: ct));
    }

    public async Task MarkUsedAsync(string id, CancellationToken ct)
    {
        const string sql = @"UPDATE mfa_challenges SET used_at_utc = @usedAt WHERE id = @id;";
        using var db = Open();
        await db.ExecuteAsync(new CommandDefinition(sql, new { id, usedAt = DateTime.UtcNow.ToString("O") }, cancellationToken: ct));
    }

    public async Task IncrementAttemptAsync(string id, CancellationToken ct)
    {
        const string sql = @"UPDATE mfa_challenges SET attempt_count = attempt_count + 1 WHERE id = @id;";
        using var db = Open();
        await db.ExecuteAsync(new CommandDefinition(sql, new { id }, cancellationToken: ct));
    }

    /// <summary>
    /// Elimina challenge scaduti o gia' usati in batch.
    /// </summary>
    public async Task<int> DeleteExpiredAsync(string nowIso, int batchSize, CancellationToken ct)
    {
        const string sql = @"
DELETE FROM mfa_challenges
WHERE rowid IN (
    SELECT rowid FROM mfa_challenges
    WHERE (expires_at_utc <= @now OR used_at_utc IS NOT NULL)
    LIMIT @batchSize
);";

        using var db = Open();
        return await db.ExecuteAsync(new CommandDefinition(sql, new { now = nowIso, batchSize }, cancellationToken: ct));
    }
}
