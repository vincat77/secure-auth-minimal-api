using Dapper;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using SecureAuthMinimalApi.Services;

namespace SecureAuthMinimalApi.Data;

/// <summary>
/// Utility per inizializzare lo schema SQLite usato dall'app.
/// </summary>
public static class DbInitializer
{
  /// <summary>
  /// Crea lo schema SQLite richiesto se assente (tabella user_sessions) e fallisce se manca la connection string.
  /// </summary>
  /// <summary>
  /// Assicura l'esistenza delle tabelle richieste nello schema SQLite.
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
);

CREATE TABLE IF NOT EXISTS user_sessions (
  session_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  created_at_utc TEXT NOT NULL,
  expires_at_utc TEXT NOT NULL,
  revoked_at_utc TEXT NULL,
  user_data_json TEXT NOT NULL,
  csrf_token TEXT NOT NULL,
  last_seen_utc TEXT NOT NULL
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
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  session_id TEXT NULL,
  token_hash TEXT NULL,
  created_at_utc TEXT NOT NULL,
  expires_at_utc TEXT NOT NULL,
  revoked_at_utc TEXT NULL,
  user_agent TEXT NULL,
  client_ip TEXT NULL,
  device_id TEXT NULL,
  device_label TEXT NULL,
  rotation_parent_id TEXT NULL,
  rotation_reason TEXT NULL
);

CREATE TABLE IF NOT EXISTS mfa_challenges (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  created_at_utc TEXT NOT NULL,
  expires_at_utc TEXT NOT NULL,
  used_at_utc TEXT NULL,
  user_agent TEXT NULL,
  client_ip TEXT NULL,
  attempt_count INTEGER NOT NULL DEFAULT 0
);";
    conn.Execute(ddl);

    // Seed utente demo/demo se non esiste (solo per ambienti di esempio).
    // Ensure new columns/indexes for existing DBs.
    EnsureColumn(conn, "users", "totp_secret");
    EnsureColumn(conn, "users", "name");
    EnsureColumn(conn, "users", "given_name");
    EnsureColumn(conn, "users", "family_name");
    EnsureColumn(conn, "users", "email");
    EnsureColumn(conn, "users", "email_normalized");
    EnsureColumn(conn, "users", "email_confirmed", "INTEGER DEFAULT 0");
    EnsureColumn(conn, "users", "email_confirm_token");
    EnsureColumn(conn, "users", "email_confirm_expires_utc");
    EnsureColumn(conn, "users", "picture_url");
    EnsureColumn(conn, "user_sessions", "last_seen_utc");
    EnsureColumn(conn, "refresh_tokens", "device_id");
    EnsureColumn(conn, "refresh_tokens", "device_label");
    EnsureColumn(conn, "refresh_tokens", "token_hash");
    conn.Execute("UPDATE user_sessions SET last_seen_utc = created_at_utc WHERE last_seen_utc IS NULL;");
    const string idxEmail = "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_normalized ON users(email_normalized);";
    conn.Execute(idxEmail);
    const string idxRefreshTokenHash = "CREATE UNIQUE INDEX IF NOT EXISTS idx_refresh_tokens_token_hash ON refresh_tokens(token_hash);";
    const string idxRefreshUser = "CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id);";
    const string idxRefreshSession = "CREATE INDEX IF NOT EXISTS idx_refresh_tokens_session ON refresh_tokens(session_id);";
    const string idxRefreshDevice = "CREATE INDEX IF NOT EXISTS idx_refresh_tokens_device ON refresh_tokens(device_id);";
    const string idxMfaUser = "CREATE INDEX IF NOT EXISTS idx_mfa_challenges_user ON mfa_challenges(user_id);";
    const string idxSessionsExpires = "CREATE INDEX IF NOT EXISTS idx_user_sessions_expires ON user_sessions(expires_at_utc);";
    const string idxSessionsRevoked = "CREATE INDEX IF NOT EXISTS idx_user_sessions_revoked ON user_sessions(revoked_at_utc);";
    const string idxRefreshExpires = "CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens(expires_at_utc);";
    const string idxRefreshRevoked = "CREATE INDEX IF NOT EXISTS idx_refresh_tokens_revoked ON refresh_tokens(revoked_at_utc);";
    const string idxMfaExpires = "CREATE INDEX IF NOT EXISTS idx_mfa_challenges_expires ON mfa_challenges(expires_at_utc);";
    const string idxMfaUsed = "CREATE INDEX IF NOT EXISTS idx_mfa_challenges_used ON mfa_challenges(used_at_utc);";
    conn.Execute(idxRefreshTokenHash);
    conn.Execute(idxRefreshUser);
    conn.Execute(idxRefreshSession);
    conn.Execute(idxRefreshDevice);
    conn.Execute(idxMfaUser);
    conn.Execute(idxSessionsExpires);
    conn.Execute(idxSessionsRevoked);
    conn.Execute(idxRefreshExpires);
    conn.Execute(idxRefreshRevoked);
    conn.Execute(idxMfaExpires);
    conn.Execute(idxMfaUsed);

    const string seedCheck = "SELECT COUNT(1) FROM users WHERE username = 'demo';";
    var exists = conn.ExecuteScalar<long>(seedCheck);
    if (exists == 0)
    {
      var demoHash = Services.PasswordHasher.Hash("123456789012");
      const string seedInsert = @"
INSERT INTO users (id, username, password_hash, created_at_utc, totp_secret, name, given_name, family_name, email, email_normalized, email_confirmed, picture_url)
VALUES (@Id, @Username, @PasswordHash, @CreatedAtUtc, NULL, @Name, @GivenName, @FamilyName, @Email, @EmailNormalized, 1, @PictureUrl);";
      conn.Execute(seedInsert, new
      {
        Id = "demo-user",
        Username = "demo",
        PasswordHash = demoHash,
        CreatedAtUtc = DateTime.UtcNow.ToString("O"),
        Name = "Demo User",
        GivenName = "Demo",
        FamilyName = "User",
        Email = "demo@example.com",
        EmailNormalized = "demo@example.com",
        PictureUrl = "https://api.dicebear.com/9.x/adventurer/svg?seed=Mason"
      });
    }
  }

  private static void EnsureColumn(SqliteConnection conn, string table, string column, string? typeOverride = null)
  {
    var pragma = conn.Query<string>($"PRAGMA table_info({table});");
    if (!pragma.Any(x => x.Contains(column, StringComparison.OrdinalIgnoreCase)))
    {
      try
      {
        conn.Execute($"ALTER TABLE {table} ADD COLUMN {column} {typeOverride ?? "TEXT NULL"};");
      }
      catch (SqliteException ex) when (ex.Message.Contains("duplicate column name", StringComparison.OrdinalIgnoreCase))
      {
        // già esiste, ignora per compatibilità
      }
    }
  }
}
