using Dapper;
using Microsoft.Data.Sqlite;
using SecureAuthMinimalApi.Utilities;
using System.Security.Cryptography;

namespace SecureAuthMinimalApi.Data;

/// <summary>
/// Seed dedicato agli smoke test: crea utenti di prova, incluso uno non confermato.
/// </summary>
public static class SmokeTestSeeder
{
    /// <summary>
    /// Crea gli utenti di prova se non già presenti.
    /// </summary>
    public static void Seed(SqliteConnection conn)
    {
        SeedUnconfirmedUser(conn);
        SeedMfaUser(conn);
        SeedResetUser(conn);
        SeedResetToken(conn);
    }

    private static void SeedUnconfirmedUser(SqliteConnection conn)
    {
        SeedUser(conn,
            id: "smoke-unconfirmed-user",
            username: "smoke-unconfirmed",
            password: "Unconfirmed123!",
            email: "smoke-unconfirmed@example.com",
            emailConfirmed: false,
            totpSecretProtected: null);
    }

    /// <summary>
    /// Utente MFA con segreto noto per smoke manuali.
    /// Segreto base32: JBSWY3DPEHPK3PXP (TOTP 6 cifre, periodo 30s, SHA1).
    /// </summary>
    private static void SeedMfaUser(SqliteConnection conn)
    {
        var totpSecretPlain = "JBSWY3DPEHPK3PXP"; // base32, classic test secret

        SeedUser(conn,
            id: "smoke-mfa-user",
            username: "smoke-mfa",
            password: "SmokeMfa123!",
            email: "smoke-mfa@example.com",
            emailConfirmed: true,
            totpSecretProtected: totpSecretPlain);
    }

    /// <summary>
    /// Utente confermato per prove reset password/login base.
    /// </summary>
    private static void SeedResetUser(SqliteConnection conn)
    {
        SeedUser(conn,
            id: "smoke-reset-user",
            username: "smoke-reset",
            password: "SmokeReset123!",
            email: "smoke-reset@example.com",
            emailConfirmed: true,
            totpSecretProtected: null);
    }

    private static void SeedUser(SqliteConnection conn, string id, string username, string password, string email, bool emailConfirmed, string? totpSecretProtected)
    {
        var exists = conn.ExecuteScalar<long>(
            "SELECT COUNT(1) FROM users WHERE username = @Username;",
            new { Username = username });

        if (exists > 0)
        {
            return;
        }

        var now = DateTime.UtcNow.ToString("O");
        var passwordHash = PasswordHasher.Hash(password);

        const string insert = @"
INSERT INTO users (
  id,
  username,
  password_hash,
  created_at_utc,
  is_locked,
  deleted_at_utc,
  totp_secret,
  name,
  given_name,
  family_name,
  email,
  email_normalized,
  email_confirmed,
  email_confirm_token,
  email_confirm_expires_utc,
  picture_url
) VALUES (
  @Id,
  @Username,
  @PasswordHash,
  @CreatedAtUtc,
  0,
  NULL,
  @TotpSecret,
  @Name,
  @GivenName,
  @FamilyName,
  @Email,
  LOWER(@Email),
  @EmailConfirmed,
  NULL,
  NULL,
  NULL
);";

        conn.Execute(insert, new
        {
            Id = id,
            Username = username,
            PasswordHash = passwordHash,
            CreatedAtUtc = now,
            TotpSecret = totpSecretProtected,
            Name = $"Smoke {username}",
            GivenName = "Smoke",
            FamilyName = username.Replace("smoke-", "", StringComparison.OrdinalIgnoreCase),
            Email = email,
            EmailConfirmed = emailConfirmed ? 1 : 0
        });
    }

    private static void SeedResetToken(SqliteConnection conn)
    {
        const string tokenPlain = "SMOKERES";
        var tokenHash = HashToken(tokenPlain);
        var now = DateTime.UtcNow;
        var exp = now.AddMinutes(30).ToString("O");

        conn.Execute("DELETE FROM password_resets WHERE user_id = @UserId;", new { UserId = "smoke-reset-user" });

        const string insert = @"
INSERT INTO password_resets (id, user_id, token_hash, expires_at_utc, used_at_utc, created_at_utc, client_ip, user_agent)
VALUES (@Id, @UserId, @TokenHash, @ExpiresAtUtc, NULL, @CreatedAtUtc, '127.0.0.1', 'smoke-seed');";

        conn.Execute(insert, new
        {
            Id = Guid.NewGuid().ToString("N"),
            UserId = "smoke-reset-user",
            TokenHash = tokenHash,
            ExpiresAtUtc = exp,
            CreatedAtUtc = now.ToString("O")
        });
    }

    private static string HashToken(string token)
    {
        using var sha = SHA256.Create();
        var bytes = System.Text.Encoding.UTF8.GetBytes(token);
        var hash = sha.ComputeHash(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
