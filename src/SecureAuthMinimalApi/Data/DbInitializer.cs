using Dapper;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using SecureAuthMinimalApi.Services;

namespace SecureAuthMinimalApi.Data;

public static class DbInitializer
{
    /// <summary>
    /// Crea lo schema SQLite richiesto se assente (tabella user_sessions) e fallisce se manca la connection string.
    /// </summary>
    public static void EnsureCreated(IConfiguration config)
    {
        var cs = config.GetConnectionString("Sqlite")
            ?? throw new InvalidOperationException("Missing ConnectionStrings:Sqlite in appsettings.json");

        using var conn = new SqliteConnection(cs);
        conn.Open();

        // Schema strictly as requested.
        const string ddl = @"
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS user_sessions (
  session_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  created_at_utc TEXT NOT NULL,
  expires_at_utc TEXT NOT NULL,
  revoked_at_utc TEXT NULL,
  user_data_json TEXT NOT NULL,
  csrf_token TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS login_throttle (
  username TEXT PRIMARY KEY,
  failures INTEGER NOT NULL,
  locked_until_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS login_audit (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL,
  outcome TEXT NOT NULL,
  timestamp_utc TEXT NOT NULL,
  client_ip TEXT NULL,
  user_agent TEXT NULL,
  detail TEXT NULL
);";
        conn.Execute(ddl);

        // Seed utente demo/demo se non esiste (solo per ambienti di esempio).
        const string seedCheck = "SELECT COUNT(1) FROM users WHERE username = 'demo';";
        var exists = conn.ExecuteScalar<long>(seedCheck);
        if (exists == 0)
        {
            var demoHash = Services.PasswordHasher.Hash("demo");
            EnsureColumn(conn, "users", "totp_secret");
            EnsureColumn(conn, "users", "email");
            EnsureColumn(conn, "users", "email_normalized");
            EnsureColumn(conn, "users", "email_confirmed", "INTEGER DEFAULT 0");
            EnsureColumn(conn, "users", "email_confirm_token");
            EnsureColumn(conn, "users", "email_confirm_expires_utc");
            const string seedInsert = @"
INSERT INTO users (id, username, password_hash, created_at_utc)
VALUES (@Id, @Username, @PasswordHash, @CreatedAtUtc);";
            conn.Execute(seedInsert, new
            {
                Id = "demo-user",
                Username = "demo",
                PasswordHash = demoHash,
                CreatedAtUtc = DateTime.UtcNow.ToString("O")
            });
        }
    }

    private static void EnsureColumn(SqliteConnection conn, string table, string column, string? typeOverride = null)
    {
        var pragma = conn.Query<string>($"PRAGMA table_info({table});");
        if (!pragma.Any(x => x.Contains(column, StringComparison.OrdinalIgnoreCase)))
        {
            conn.Execute($"ALTER TABLE {table} ADD COLUMN {column} {typeOverride ?? "TEXT NULL"};");
        }
    }
}
