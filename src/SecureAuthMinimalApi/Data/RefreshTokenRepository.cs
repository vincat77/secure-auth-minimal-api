using System.Data;
using Dapper;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using SecureAuthMinimalApi.Models;
using SecureAuthMinimalApi.Services;

namespace SecureAuthMinimalApi.Data;

/// <summary>
/// Accesso e gestione dei token di refresh persistenti.
/// </summary>
public sealed class RefreshTokenRepository
{
    private readonly string _connectionString;
    private readonly RefreshTokenHasher _hasher;

    /// <summary>
    /// Inizializza repository refresh token con connection string e hasher.
    /// </summary>
    public RefreshTokenRepository(IConfiguration config, RefreshTokenHasher hasher)
    {
        _connectionString = config.GetConnectionString("Sqlite")
            ?? throw new InvalidOperationException("Missing ConnectionStrings:Sqlite in appsettings.json");
        _hasher = hasher;
    }

    private IDbConnection Open() => new SqliteConnection(_connectionString);

    /// <summary>
    /// Inserisce un nuovo refresh token associato alla sessione.
    /// </summary>
    public async Task CreateAsync(RefreshToken token, CancellationToken ct)
    {
        const string sql = @"
INSERT INTO refresh_tokens (id, user_id, session_id, token_hash, created_at_utc, expires_at_utc, revoked_at_utc, user_agent, client_ip, device_id, device_label, rotation_parent_id, rotation_reason)
VALUES (@Id, @UserId, @SessionId, @TokenHash, @CreatedAtUtc, @ExpiresAtUtc, @RevokedAtUtc, @UserAgent, @ClientIp, @DeviceId, @DeviceLabel, @RotationParentId, @RotationReason);";

        var tokenHash = _hasher.ComputeHash(token.Token);
        using var db = Open();
        await db.ExecuteAsync(new CommandDefinition(sql, new
        {
            token.Id,
            token.UserId,
            token.SessionId,
            TokenHash = tokenHash,
            token.CreatedAtUtc,
            token.ExpiresAtUtc,
            token.RevokedAtUtc,
            token.UserAgent,
            token.ClientIp,
            token.DeviceId,
            token.DeviceLabel,
            token.RotationParentId,
            token.RotationReason
        }, cancellationToken: ct));
    }

    /// <summary>
    /// Cerca un refresh token valido tramite valore in chiaro.
    /// </summary>
    public async Task<RefreshToken?> GetByTokenAsync(string tokenValue, CancellationToken ct)
    {
        const string sql = @"
SELECT id AS Id, user_id AS UserId, session_id AS SessionId, token_hash AS TokenHash, created_at_utc AS CreatedAtUtc,
       expires_at_utc AS ExpiresAtUtc, revoked_at_utc AS RevokedAtUtc, user_agent AS UserAgent, client_ip AS ClientIp,
       device_id AS DeviceId, device_label AS DeviceLabel,
       rotation_parent_id AS RotationParentId, rotation_reason AS RotationReason
FROM refresh_tokens
WHERE token_hash = @tokenHash
LIMIT 1;";

        var tokenHash = _hasher.ComputeHash(tokenValue);
        using var db = Open();
        return await db.QuerySingleOrDefaultAsync<RefreshToken>(new CommandDefinition(sql, new { tokenHash }, cancellationToken: ct));
    }

    /// <summary>
    /// Revoca un refresh token sentito l'id specifico.
    /// </summary>
    public async Task RevokeByIdAsync(string id, string reason, CancellationToken ct)
    {
        const string sql = @"
UPDATE refresh_tokens
SET revoked_at_utc = @revokedAt, rotation_reason = @reason
WHERE id = @id;";

        using var db = Open();
        await db.ExecuteAsync(new CommandDefinition(sql, new
        {
            id,
            revokedAt = DateTime.UtcNow.ToString("O"),
            reason
        }, cancellationToken: ct));
    }

    /// <summary>
    /// Revoca un token fornendo il valore originale (non hash).
    /// </summary>
    public async Task RevokeByTokenAsync(string tokenValue, string reason, CancellationToken ct)
    {
        const string sql = @"
UPDATE refresh_tokens
SET revoked_at_utc = @revokedAt, rotation_reason = @reason
WHERE token_hash = @tokenHash;";

        var tokenHash = _hasher.ComputeHash(tokenValue);
        using var db = Open();
        await db.ExecuteAsync(new CommandDefinition(sql, new
        {
            tokenHash,
            revokedAt = DateTime.UtcNow.ToString("O"),
            reason
        }, cancellationToken: ct));
    }

    /// <summary>
    /// Ruota il token esistente inserendo uno nuovo e segnando il precedente come revocato.
    /// </summary>
    public async Task RotateAsync(string oldId, RefreshToken newToken, string reason, CancellationToken ct)
    {
        using var db = Open();
        await ((SqliteConnection)db).OpenAsync(ct);
        using var tx = db.BeginTransaction();

        const string revokeSql = @"
UPDATE refresh_tokens
SET revoked_at_utc = @revokedAt, rotation_reason = @reason
WHERE id = @id;";

        await db.ExecuteAsync(new CommandDefinition(revokeSql, new
        {
            id = oldId,
            revokedAt = DateTime.UtcNow.ToString("O"),
            reason
        }, transaction: tx, cancellationToken: ct));

        const string insertSql = @"
INSERT INTO refresh_tokens (id, user_id, session_id, token_hash, created_at_utc, expires_at_utc, revoked_at_utc, user_agent, client_ip, device_id, device_label, rotation_parent_id, rotation_reason)
VALUES (@Id, @UserId, @SessionId, @TokenHash, @CreatedAtUtc, @ExpiresAtUtc, @RevokedAtUtc, @UserAgent, @ClientIp, @DeviceId, @DeviceLabel, @RotationParentId, @RotationReason);";

        var tokenHash = _hasher.ComputeHash(newToken.Token);
        await db.ExecuteAsync(new CommandDefinition(insertSql, new
        {
            newToken.Id,
            newToken.UserId,
            newToken.SessionId,
            TokenHash = tokenHash,
            newToken.CreatedAtUtc,
            newToken.ExpiresAtUtc,
            newToken.RevokedAtUtc,
            newToken.UserAgent,
            newToken.ClientIp,
            newToken.DeviceId,
            newToken.DeviceLabel,
            RotationParentId = newToken.RotationParentId ?? oldId,
            newToken.RotationReason
        }, transaction: tx, cancellationToken: ct));

        tx.Commit();
    }

    /// <summary>
    /// Revoca tutti i refresh token attivi per l'utente.
    /// </summary>
    public async Task RevokeAllForUserAsync(string userId, string reason, CancellationToken ct, IDbConnection? connection = null, IDbTransaction? tx = null)
    {
        const string sql = @"
UPDATE refresh_tokens
SET revoked_at_utc = @revokedAt, rotation_reason = @reason
WHERE user_id = @userId AND revoked_at_utc IS NULL;";

        var db = connection ?? Open();
        await db.ExecuteAsync(new CommandDefinition(sql, new
        {
            userId,
            revokedAt = DateTime.UtcNow.ToString("O"),
            reason
        }, transaction: tx, cancellationToken: ct));
    }

    /// <summary>
    /// Elimina refresh scaduti o revocati in batch.
    /// </summary>
    /// <summary>
    /// Elimina token scaduti o revocati in batch.
    /// </summary>
    public async Task<int> DeleteExpiredAsync(string nowIso, int batchSize, CancellationToken ct)
    {
        const string sql = @"
DELETE FROM refresh_tokens
WHERE rowid IN (
    SELECT rowid FROM refresh_tokens
    WHERE (expires_at_utc <= @now OR revoked_at_utc IS NOT NULL)
    LIMIT @batchSize
);";

        using var db = Open();
        return await db.ExecuteAsync(new CommandDefinition(sql, new { now = nowIso, batchSize }, cancellationToken: ct));
    }
}
