using System.Data;
using Dapper;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using SecureAuthMinimalApi.Models;
using SecureAuthMinimalApi.Services;

namespace SecureAuthMinimalApi.Data;

/// <summary>
/// Accesso a utenti (creazione e lookup per username).
/// </summary>
public sealed class UserRepository
{
    private readonly string _connectionString;
    private readonly TotpSecretProtector _protector;

    public UserRepository(IConfiguration config, TotpSecretProtector protector)
    {
        _connectionString = config.GetConnectionString("Sqlite")
            ?? throw new InvalidOperationException("Missing ConnectionStrings:Sqlite in appsettings.json");
        _protector = protector;
    }

    private IDbConnection Open() => new SqliteConnection(_connectionString);

    public async Task CreateAsync(User user, CancellationToken ct)
    {
        const string sql = @"
INSERT INTO users (id, username, password_hash, created_at_utc, totp_secret)
VALUES (@Id, @Username, @PasswordHash, @CreatedAtUtc, @TotpSecret);";

        using var db = Open();
        await db.ExecuteAsync(new CommandDefinition(sql, new
        {
            user.Id,
            user.Username,
            user.PasswordHash,
            user.CreatedAtUtc,
            TotpSecret = string.IsNullOrWhiteSpace(user.TotpSecret) ? null : _protector.Protect(user.TotpSecret)
        }, cancellationToken: ct));
    }

    public async Task<User?> GetByUsernameAsync(string username, CancellationToken ct)
    {
        const string sql = @"
SELECT id AS Id, username AS Username, password_hash AS PasswordHash, created_at_utc AS CreatedAtUtc, totp_secret AS TotpSecret
FROM users
WHERE username = @username
LIMIT 1;";

        using var db = Open();
        var row = await db.QuerySingleOrDefaultAsync<User>(new CommandDefinition(sql, new { username }, cancellationToken: ct));
        return DecryptTotp(row);
    }
    public async Task<User?> GetByIdAsync(string userId, CancellationToken ct)
    {
        const string sql = @"
SELECT id AS Id, username AS Username, password_hash AS PasswordHash, created_at_utc AS CreatedAtUtc, totp_secret AS TotpSecret
FROM users
WHERE id = @userId
LIMIT 1;";

        using var db = Open();
        var row = await db.QuerySingleOrDefaultAsync<User>(new CommandDefinition(sql, new { userId }, cancellationToken: ct));
        return DecryptTotp(row);
    }

    public async Task SetTotpSecretAsync(string userId, string secret, CancellationToken ct)
    {
        const string sql = @"
UPDATE users
SET totp_secret = @secret
WHERE id = @userId;";

        using var db = Open();
        var cipher = _protector.Protect(secret);
        await db.ExecuteAsync(new CommandDefinition(sql, new { userId, secret = cipher }, cancellationToken: ct));
    }

    public async Task ClearTotpSecretAsync(string userId, CancellationToken ct)
    {
        const string sql = @"
UPDATE users
SET totp_secret = NULL
WHERE id = @userId;";

        using var db = Open();
        await db.ExecuteAsync(new CommandDefinition(sql, new { userId }, cancellationToken: ct));
    }

    private User? DecryptTotp(User? user)
    {
        if (user is null)
            return null;

        if (!string.IsNullOrWhiteSpace(user.TotpSecret))
        {
            var plain = _protector.Unprotect(user.TotpSecret);
            user = new User
            {
                Id = user.Id,
                Username = user.Username,
                PasswordHash = user.PasswordHash,
                CreatedAtUtc = user.CreatedAtUtc,
                TotpSecret = string.IsNullOrWhiteSpace(plain) ? null : plain
            };
        }

        return user;
    }
}
