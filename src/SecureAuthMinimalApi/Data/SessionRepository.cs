using System.Data;
using Dapper;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using SecureAuthMinimalApi.Models;

namespace SecureAuthMinimalApi.Data;

/// <summary>
/// Accesso a user_sessions via Dapper: crea, legge, revoca.
/// </summary>
public sealed class SessionRepository
{
    private readonly string _connectionString;

    public SessionRepository(IConfiguration config)
    {
        _connectionString = config.GetConnectionString("Sqlite")
            ?? throw new InvalidOperationException("Missing ConnectionStrings:Sqlite in appsettings.json");
    }

    private IDbConnection Open() => new SqliteConnection(_connectionString);

    /// <summary>
    /// Inserisce una nuova sessione.
    /// </summary>
    public async Task CreateAsync(UserSession session, CancellationToken ct)
    {
        const string sql = @"
INSERT INTO user_sessions (
  session_id, user_id, created_at_utc, expires_at_utc, revoked_at_utc, user_data_json, csrf_token, last_seen_utc
) VALUES (
  @SessionId, @UserId, @CreatedAtUtc, @ExpiresAtUtc, @RevokedAtUtc, @UserDataJson, @CsrfToken, @LastSeenUtc
);";
        using var db = Open();
        await db.ExecuteAsync(new CommandDefinition(sql, session, cancellationToken: ct));
    }

    /// <summary>
    /// Restituisce una sessione per id o null se assente.
    /// </summary>
    public async Task<UserSession?> GetByIdAsync(string sessionId, CancellationToken ct)
    {
        const string sql = @"
SELECT
  session_id   AS SessionId,
  user_id      AS UserId,
  created_at_utc AS CreatedAtUtc,
  expires_at_utc AS ExpiresAtUtc,
  revoked_at_utc AS RevokedAtUtc,
  user_data_json AS UserDataJson,
  csrf_token     AS CsrfToken,
  last_seen_utc  AS LastSeenUtc
FROM user_sessions
WHERE session_id = @sessionId
LIMIT 1;";
        using var db = Open();
        return await db.QuerySingleOrDefaultAsync<UserSession>(new CommandDefinition(sql, new { sessionId }, cancellationToken: ct));
    }

    /// <summary>
    /// Marca la sessione come revocata impostando revoked_at_utc.
    /// </summary>
    public async Task RevokeAsync(string sessionId, string revokedAtUtcIso, CancellationToken ct)
    {
        const string sql = @"
UPDATE user_sessions
SET revoked_at_utc = @revokedAtUtcIso
WHERE session_id = @sessionId;";
        using var db = Open();
        await db.ExecuteAsync(new CommandDefinition(sql, new { sessionId, revokedAtUtcIso }, cancellationToken: ct));
    }

    /// <summary>
    /// Aggiorna last_seen_utc per la sessione (idle timeout).
    /// </summary>
    public async Task UpdateLastSeenAsync(string sessionId, string lastSeenUtcIso, CancellationToken ct)
    {
        const string sql = @"
UPDATE user_sessions
SET last_seen_utc = @lastSeenUtcIso
WHERE session_id = @sessionId;";
        using var db = Open();
        await db.ExecuteAsync(new CommandDefinition(sql, new { sessionId, lastSeenUtcIso }, cancellationToken: ct));
    }
}
