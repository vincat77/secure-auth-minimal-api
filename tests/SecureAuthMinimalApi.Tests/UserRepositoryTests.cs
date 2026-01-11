using Microsoft.Extensions.Configuration;
using SecureAuthMinimalApi.Data;
using SecureAuthMinimalApi.Services;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Dapper;
using Xunit;

namespace SecureAuthMinimalApi.Tests;

public class UserRepositoryTests
{
    [Fact]
    public async Task UpdatePasswordAsync_updates_hash_in_db()
    {
        // Scenario: chiama UpdatePasswordAsync su un utente e poi legge il DB per verificare che l'hash sia cambiato.
        // Risultato atteso: hash password aggiornato nel database.
        var dbPath = Path.Combine(Path.GetTempPath(), $"userrepo-{Guid.NewGuid():N}.db");
        try
        {
            var cs = $"Data Source={dbPath};Mode=ReadWriteCreate;Cache=Shared";
            await using (var conn = new SqliteConnection(cs))
            {
                await conn.OpenAsync();
                await conn.ExecuteAsync(@"
CREATE TABLE users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at_utc TEXT NOT NULL,
  totp_secret TEXT NULL,
  name TEXT NULL,
  given_name TEXT NULL,
  family_name TEXT NULL,
  email TEXT NULL,
  email_normalized TEXT NULL,
  email_confirmed INTEGER DEFAULT 0,
  email_confirm_token TEXT NULL,
  email_confirm_expires_utc TEXT NULL,
  picture_url TEXT NULL
);");
                await conn.ExecuteAsync("INSERT INTO users (id, username, password_hash, created_at_utc) VALUES (@id, @u, @p, @created);",
                    new { id = "u1", u = "demo", p = "oldhash", created = DateTime.UtcNow.ToString("O") });
            }

            var cfg = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?> { ["ConnectionStrings:Sqlite"] = cs })
                .Build();
            var dp = DataProtectionProvider.Create("tests");
            var protector = new TotpSecretProtector(dp);
            var repo = new UserRepository(cfg, protector);

            await repo.UpdatePasswordAsync("u1", "newhash", CancellationToken.None);

            await using var check = new SqliteConnection(cs);
            await check.OpenAsync();
            var stored = await check.ExecuteScalarAsync<string>("SELECT password_hash FROM users WHERE id = 'u1';");
            Assert.Equal("newhash", stored);
        }
        finally
        {
            if (File.Exists(dbPath))
            {
                try { File.Delete(dbPath); } catch { }
            }
        }
    }
}
