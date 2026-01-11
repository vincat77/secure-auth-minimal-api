using System.Data;
using Dapper;
using Microsoft.Data.Sqlite;
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

    /// <summary>
    /// Inizializza repository utenti con connection string e protezione TOTP.
    /// </summary>
    public UserRepository(IConfiguration config, TotpSecretProtector protector)
    {
        _connectionString = config.GetConnectionString("Sqlite")
            ?? throw new InvalidOperationException("Missing ConnectionStrings:Sqlite in appsettings.json");
        _protector = protector;
    }

    private IDbConnection Open() => new SqliteConnection(_connectionString);

    /// <summary>
    /// Inserisce un nuovo utente e salva il segreto TOTP crittografato.
    /// </summary>
    public async Task CreateAsync(User user, CancellationToken ct)
    {
        const string sql = @"
INSERT INTO users (id, username, password_hash, created_at_utc, totp_secret, name, given_name, family_name, email, email_normalized, email_confirmed, email_confirm_token, email_confirm_expires_utc, picture_url)
VALUES (@Id, @Username, @PasswordHash, @CreatedAtUtc, @TotpSecret, @Name, @GivenName, @FamilyName, @Email, @EmailNormalized, @EmailConfirmed, @EmailConfirmToken, @EmailConfirmExpiresUtc, @PictureUrl);";

        using var db = Open();
        await db.ExecuteAsync(new CommandDefinition(sql, new
        {
            user.Id,
            user.Username,
            user.PasswordHash,
            user.CreatedAtUtc,
            TotpSecret = string.IsNullOrWhiteSpace(user.TotpSecret) ? null : _protector.Protect(user.TotpSecret),
            user.Name,
            user.GivenName,
            user.FamilyName,
            user.Email,
            user.EmailNormalized,
            user.EmailConfirmed,
            user.EmailConfirmToken,
            user.EmailConfirmExpiresUtc,
            user.PictureUrl
        }, cancellationToken: ct));
    }

    /// <summary>
    /// Recupera l'utente corrispondente allo username (case insensitive).
    /// </summary>
    public async Task<User?> GetByUsernameAsync(string username, CancellationToken ct)
    {
        const string sql = @"
SELECT id AS Id, username AS Username, password_hash AS PasswordHash, created_at_utc AS CreatedAtUtc, totp_secret AS TotpSecret,
       is_locked AS IsLocked, deleted_at_utc AS DeletedAtUtc,
       name AS Name, given_name AS GivenName, family_name AS FamilyName,
       email AS Email, email_normalized AS EmailNormalized, email_confirmed AS EmailConfirmed,
       email_confirm_token AS EmailConfirmToken, email_confirm_expires_utc AS EmailConfirmExpiresUtc,
       picture_url AS PictureUrl
FROM users
WHERE username = @username OR username = @normalized
LIMIT 1;";

        using var db = Open();
        var row = await db.QuerySingleOrDefaultAsync<User>(new CommandDefinition(sql, new { username, normalized = username.ToLowerInvariant() }, cancellationToken: ct));
        return DecryptTotp(row);
    }
    /// <summary>
    /// Legge l'utente tramite l'identificativo primario.
    /// </summary>
    public async Task<User?> GetByIdAsync(string userId, CancellationToken ct)
    {
        const string sql = @"
SELECT id AS Id, username AS Username, password_hash AS PasswordHash, created_at_utc AS CreatedAtUtc, totp_secret AS TotpSecret,
       is_locked AS IsLocked, deleted_at_utc AS DeletedAtUtc,
       name AS Name, given_name AS GivenName, family_name AS FamilyName,
       email AS Email, email_normalized AS EmailNormalized, email_confirmed AS EmailConfirmed,
       email_confirm_token AS EmailConfirmToken, email_confirm_expires_utc AS EmailConfirmExpiresUtc,
       picture_url AS PictureUrl
FROM users
WHERE id = @userId
LIMIT 1;";

        using var db = Open();
        var row = await db.QuerySingleOrDefaultAsync<User>(new CommandDefinition(sql, new { userId }, cancellationToken: ct));
        return DecryptTotp(row);
    }

    /// <summary>
    /// Cerca l'utente tramite email normalizzata.
    /// </summary>
    public async Task<User?> GetByEmailAsync(string emailNormalized, CancellationToken ct)
    {
        const string sql = @"
SELECT id AS Id, username AS Username, password_hash AS PasswordHash, created_at_utc AS CreatedAtUtc, totp_secret AS TotpSecret,
       is_locked AS IsLocked, deleted_at_utc AS DeletedAtUtc,
       name AS Name, given_name AS GivenName, family_name AS FamilyName,
       email AS Email, email_normalized AS EmailNormalized, email_confirmed AS EmailConfirmed,
       email_confirm_token AS EmailConfirmToken, email_confirm_expires_utc AS EmailConfirmExpiresUtc,
       picture_url AS PictureUrl
FROM users
WHERE email_normalized = @email
LIMIT 1;";

        using var db = Open();
        var row = await db.QuerySingleOrDefaultAsync<User>(new CommandDefinition(sql, new { email = emailNormalized }, cancellationToken: ct));
        return DecryptTotp(row);
    }

    /// <summary>
    /// Recupera l'utente in base al token di conferma email.
    /// </summary>
    public async Task<User?> GetByEmailTokenAsync(string token, CancellationToken ct)
    {
        const string sql = @"
SELECT id AS Id, username AS Username, password_hash AS PasswordHash, created_at_utc AS CreatedAtUtc, totp_secret AS TotpSecret,
       is_locked AS IsLocked, deleted_at_utc AS DeletedAtUtc,
       name AS Name, given_name AS GivenName, family_name AS FamilyName,
       email AS Email, email_normalized AS EmailNormalized, email_confirmed AS EmailConfirmed,
       email_confirm_token AS EmailConfirmToken, email_confirm_expires_utc AS EmailConfirmExpiresUtc,
       picture_url AS PictureUrl
FROM users
WHERE email_confirm_token = @token
LIMIT 1;";

        using var db = Open();
        var row = await db.QuerySingleOrDefaultAsync<User>(new CommandDefinition(sql, new { token }, cancellationToken: ct));
        return DecryptTotp(row);
    }

    /// <summary>
    /// Marca l'email come confermata cancellando token e scadenza.
    /// </summary>
    public async Task ConfirmEmailAsync(string userId, CancellationToken ct)
    {
        const string sql = @"
UPDATE users
SET email_confirmed = 1,
    email_confirm_token = NULL,
    email_confirm_expires_utc = NULL
WHERE id = @userId;";

        using var db = Open();
        await db.ExecuteAsync(new CommandDefinition(sql, new { userId }, cancellationToken: ct));
    }

    /// <summary>
    /// Salva il segreto TOTP criptato per l'utente.
    /// </summary>
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

    /// <summary>
    /// Rimuove il segreto TOTP, disabilitando MFA.
    /// </summary>
    public async Task ClearTotpSecretAsync(string userId, CancellationToken ct)
    {
        const string sql = @"
UPDATE users
SET totp_secret = NULL
WHERE id = @userId;";

        using var db = Open();
        await db.ExecuteAsync(new CommandDefinition(sql, new { userId }, cancellationToken: ct));
    }

    /// <summary>
    /// Rigenera il token di conferma email e la relativa scadenza.
    /// </summary>
    public async Task UpdateEmailConfirmTokenAsync(string userId, string token, string expiresUtcIso, CancellationToken ct, IDbConnection? connection = null, IDbTransaction? tx = null)
    {
        const string sql = @"
UPDATE users
SET email_confirm_token = @token,
    email_confirm_expires_utc = @expiresUtcIso,
    email_confirmed = 0
WHERE id = @userId;";

        var db = connection ?? Open();
        await db.ExecuteAsync(new CommandDefinition(sql, new { userId, token, expiresUtcIso }, transaction: tx, cancellationToken: ct));
    }

    /// <summary>
    /// Aggiorna l'hash della password per l'utente.
    /// </summary>
    public async Task UpdatePasswordAsync(string userId, string passwordHash, CancellationToken ct, IDbConnection? connection = null, IDbTransaction? tx = null)
    {
        const string sql = @"
UPDATE users
SET password_hash = @passwordHash
WHERE id = @userId;";

        var db = connection ?? Open();
        await db.ExecuteAsync(new CommandDefinition(sql, new { userId, passwordHash }, transaction: tx, cancellationToken: ct));
    }

    /// <summary>
    /// Aggiorna l'email per un utente non confermato rigenerando token e scadenza.
    /// </summary>
    public async Task UpdateEmailAsync(string userId, string email, string emailNormalized, string confirmToken, string confirmExpiresUtc, CancellationToken ct, IDbConnection? connection = null, IDbTransaction? tx = null)
    {
        const string sql = @"
UPDATE users
SET email = @email,
    email_normalized = @emailNormalized,
    email_confirmed = 0,
    email_confirm_token = @confirmToken,
    email_confirm_expires_utc = @confirmExpiresUtc
WHERE id = @userId;";

        var db = connection ?? Open();
        await db.ExecuteAsync(new CommandDefinition(sql, new { userId, email, emailNormalized, confirmToken, confirmExpiresUtc }, transaction: tx, cancellationToken: ct));
    }

    private User? DecryptTotp(User? user)
    {
        if (user is null)
            return null;

        if (!string.IsNullOrWhiteSpace(user.TotpSecret))
        {
            var plain = _protector.Unprotect(user.TotpSecret);
            if (string.IsNullOrWhiteSpace(plain))
            {
                // Fallback per segreti memorizzati in chiaro (es. seeding smoke)
                plain = user.TotpSecret;
            }
            user = new User
            {
                Id = user.Id,
                Username = user.Username,
                PasswordHash = user.PasswordHash,
                CreatedAtUtc = user.CreatedAtUtc,
                TotpSecret = string.IsNullOrWhiteSpace(plain) ? null : plain,
                Name = user.Name,
                GivenName = user.GivenName,
                FamilyName = user.FamilyName,
                Email = user.Email,
                EmailNormalized = user.EmailNormalized,
                EmailConfirmed = user.EmailConfirmed,
                EmailConfirmToken = user.EmailConfirmToken,
                EmailConfirmExpiresUtc = user.EmailConfirmExpiresUtc,
                PictureUrl = user.PictureUrl
            };
        }

        return user;
    }
}
