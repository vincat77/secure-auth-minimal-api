using System.Data;
using Dapper;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using SecureAuthMinimalApi.Models;

namespace SecureAuthMinimalApi.Data;

/// <summary>
/// Accesso ai token di reset password.
/// </summary>
public sealed class PasswordResetRepository
{
    private readonly string _connectionString;

    public PasswordResetRepository(IConfiguration config)
    {
        _connectionString = config.GetConnectionString("Sqlite")
            ?? throw new InvalidOperationException("Missing ConnectionStrings:Sqlite in appsettings.json");
    }

    private IDbConnection Open() => new SqliteConnection(_connectionString);

    /// <summary>
    /// Crea un nuovo reset token (token_hash già calcolato a monte).
    /// </summary>
    public async Task CreateAsync(PasswordReset reset, CancellationToken ct, IDbTransaction? tx = null, IDbConnection? connection = null)
    {
        const string sql = @"
INSERT INTO password_resets (id, user_id, token_hash, expires_at_utc, used_at_utc, created_at_utc, client_ip, user_agent)
VALUES (@Id, @UserId, @TokenHash, @ExpiresAtUtc, @UsedAtUtc, @CreatedAtUtc, @ClientIp, @UserAgent);";

        var db = connection ?? Open();
        await db.ExecuteAsync(new CommandDefinition(sql, reset, transaction: tx, cancellationToken: ct));
    }

    /// <summary>
    /// Marca come usati eventuali reset attivi precedenti per l'utente.
    /// </summary>
    public async Task InvalidatePreviousForUserAsync(string userId, string nowIso, CancellationToken ct, IDbTransaction? tx = null, IDbConnection? connection = null)
    {
        const string sql = @"
UPDATE password_resets
SET used_at_utc = @nowIso
WHERE user_id = @userId AND used_at_utc IS NULL AND expires_at_utc > @nowIso;";

        var db = connection ?? Open();
        await db.ExecuteAsync(new CommandDefinition(sql, new { userId, nowIso }, transaction: tx, cancellationToken: ct));
    }

    /// <summary>
    /// Recupera un reset tramite hash del token.
    /// </summary>
    public async Task<PasswordReset?> GetByTokenHashAsync(string tokenHash, CancellationToken ct, IDbTransaction? tx = null, IDbConnection? connection = null)
    {
        const string sql = @"
SELECT id       AS Id,
       user_id  AS UserId,
       token_hash AS TokenHash,
       expires_at_utc AS ExpiresAtUtc,
       used_at_utc AS UsedAtUtc,
       created_at_utc AS CreatedAtUtc,
       client_ip AS ClientIp,
       user_agent AS UserAgent
FROM password_resets
WHERE token_hash = @tokenHash
LIMIT 1;";

        var db = connection ?? Open();
        return await db.QuerySingleOrDefaultAsync<PasswordReset>(new CommandDefinition(sql, new { tokenHash }, transaction: tx, cancellationToken: ct));
    }

    /// <summary>
    /// Marca il reset come usato se non già usato; restituisce righe interessate (0 se giù usato).
    /// </summary>
    public async Task<int> MarkUsedAsync(string id, string usedAtIso, CancellationToken ct, IDbTransaction? tx = null, IDbConnection? connection = null)
    {
        const string sql = @"
UPDATE password_resets
SET used_at_utc = @usedAtIso
WHERE id = @id AND used_at_utc IS NULL;";

        var db = connection ?? Open();
        return await db.ExecuteAsync(new CommandDefinition(sql, new { id, usedAtIso }, transaction: tx, cancellationToken: ct));
    }

    /// <summary>
    /// Elimina reset scaduti o già usati in batch.
    /// </summary>
    public async Task<int> DeleteExpiredAsync(string nowIso, int batchSize, CancellationToken ct)
    {
        const string sql = @"
DELETE FROM password_resets
WHERE rowid IN (
    SELECT rowid FROM password_resets
    WHERE expires_at_utc <= @nowIso OR used_at_utc IS NOT NULL
    LIMIT @batchSize
);";

        using var db = Open();
        return await db.ExecuteAsync(new CommandDefinition(sql, new { nowIso, batchSize }, cancellationToken: ct));
    }
}
