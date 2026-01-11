using Dapper;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SecureAuthMinimalApi.Data;
using SecureAuthMinimalApi.Models;
using SecureAuthMinimalApi.Options;
using SecureAuthMinimalApi.Services;
using Xunit;

namespace SecureAuthMinimalApi.Tests;

/// <summary>
/// Test del repository refresh token (CRUD, rotazione, revoca).
/// </summary>
public class RefreshTokenRepositoryTests : IAsyncLifetime
{
    private string _dbPath = null!;
    private RefreshTokenRepository _repo = null!;
    private IConfiguration _config = null!;
    private RefreshTokenHasher _hasher = null!;

    public Task InitializeAsync()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), $"refresh-tests-{Guid.NewGuid():N}.db");
        _config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:Sqlite"] = $"Data Source={_dbPath};Mode=ReadWriteCreate;Cache=Shared",
                ["Refresh:HmacKey"] = "TEST_REFRESH_HMAC_KEY_32_CHARS_MIN_LEN__"
            })
            .Build();

        DbInitializer.EnsureCreated(_config, new TestEnv(), NullLogger.Instance);
        var refreshOpts = Microsoft.Extensions.Options.Options.Create(new RefreshOptions { HmacKey = _config["Refresh:HmacKey"] });
        var jwtOpts = Microsoft.Extensions.Options.Options.Create(new JwtOptions { SecretKey = _config["Refresh:HmacKey"] ?? "TEST_REFRESH_HMAC_KEY_32_CHARS_MIN_LEN__" });
        _hasher = new RefreshTokenHasher(refreshOpts, jwtOpts);
        _repo = new RefreshTokenRepository(_config, _hasher);
        return Task.CompletedTask;
    }

    public Task DisposeAsync()
    {
        if (File.Exists(_dbPath))
        {
            try { File.Delete(_dbPath); } catch { }
        }
        return Task.CompletedTask;
    }

    private static RefreshToken NewToken(string userId, string? sessionId = null, string? parentId = null)
    {
        var now = DateTime.UtcNow;
        return new RefreshToken
        {
            Id = Guid.NewGuid().ToString("N"),
            UserId = userId,
            SessionId = sessionId,
            Token = $"tok_{Guid.NewGuid():N}",
            TokenHash = null,
            RefreshCsrfHash = null,
            CreatedAtUtc = now.ToString("O"),
            ExpiresAtUtc = now.AddDays(7).ToString("O"),
            RevokedAtUtc = null,
            UserAgent = "TestAgent",
            ClientIp = "127.0.0.1",
            RotationParentId = parentId,
            RotationReason = null
        };
    }

    [Fact]
    public async Task Create_and_get_by_token_returns_record()
    {
        // Scenario: inserisce un refresh token tramite repository e poi lo recupera con GetByTokenAsync.
        // Risultato atteso: il record inserito viene restituito correttamente.
        var token = NewToken("user1");
        await _repo.CreateAsync(token, CancellationToken.None);

        var loaded = await _repo.GetByTokenAsync(token.Token, CancellationToken.None);
        Assert.NotNull(loaded);
        Assert.Equal(token.Id, loaded!.Id);
        Assert.Equal(token.UserId, loaded.UserId);
        Assert.False(string.IsNullOrWhiteSpace(loaded.TokenHash));
        Assert.True(string.IsNullOrWhiteSpace(loaded.Token));
        Assert.Null(loaded.RevokedAtUtc);
    }

    [Fact]
    public async Task Rotate_revokes_old_and_inserts_new()
    {
        // Scenario: ruota un refresh token esistente: l'attuale viene revocato e un nuovo token viene inserito con riferimento al precedente.
        // Risultato atteso: vecchio token revocato, nuovo token presente con parent linkage.
        var oldToken = NewToken("user2", sessionId: "sess-old");
        await _repo.CreateAsync(oldToken, CancellationToken.None);

        var newToken = NewToken("user2", sessionId: "sess-old", parentId: oldToken.Id);
        await _repo.RotateAsync(oldToken.Id, newToken, "rotated", CancellationToken.None);

        await using var db = new SqliteConnection($"Data Source={_dbPath};Mode=ReadWriteCreate;Cache=Shared");
        await db.OpenAsync();
        var revoked = await db.ExecuteScalarAsync<string>("SELECT revoked_at_utc FROM refresh_tokens WHERE id = @id", new { id = oldToken.Id });
        Assert.False(string.IsNullOrWhiteSpace(revoked));

        var parentId = await db.ExecuteScalarAsync<string>("SELECT rotation_parent_id FROM refresh_tokens WHERE id = @id", new { id = newToken.Id });
        Assert.Equal(oldToken.Id, parentId);
        var tokenHash = await db.ExecuteScalarAsync<string>("SELECT token_hash FROM refresh_tokens WHERE id = @id", new { id = newToken.Id });
        Assert.False(string.IsNullOrWhiteSpace(tokenHash));
    }

    [Fact]
    public async Task Revoke_all_for_user_revokes_only_target_user()
    {
        // Scenario: chiama RevokeAllForUserAsync per un utente specifico in presenza di token di altri utenti.
        // Risultato atteso: revocati solo i token dell'utente target, gli altri restano validi.
        var t1 = NewToken("userA");
        var t2 = NewToken("userA");
        var t3 = NewToken("userB");
        await _repo.CreateAsync(t1, CancellationToken.None);
        await _repo.CreateAsync(t2, CancellationToken.None);
        await _repo.CreateAsync(t3, CancellationToken.None);

        await _repo.RevokeAllForUserAsync("userA", "logout-all", CancellationToken.None);

        await using var db = new SqliteConnection($"Data Source={_dbPath};Mode=ReadWriteCreate;Cache=Shared");
        await db.OpenAsync();
        var revokedA = await db.QueryAsync<string>("SELECT revoked_at_utc FROM refresh_tokens WHERE user_id = 'userA';");
        Assert.All(revokedA, r => Assert.False(string.IsNullOrWhiteSpace(r)));
        var revokedB = await db.ExecuteScalarAsync<string>("SELECT revoked_at_utc FROM refresh_tokens WHERE id = @id", new { id = t3.Id });
        Assert.True(string.IsNullOrWhiteSpace(revokedB));
    }

    [Fact]
    public async Task Revoke_by_id_sets_revoked()
    {
        // Scenario: revoca un refresh token specifico passando l'ID.
        // Risultato atteso: campo revoked valorizzato per quel token.
        var token = NewToken("userC");
        await _repo.CreateAsync(token, CancellationToken.None);

        await _repo.RevokeByIdAsync(token.Id, "logout", CancellationToken.None);

        var loaded = await _repo.GetByTokenAsync(token.Token, CancellationToken.None);
        Assert.NotNull(loaded);
        Assert.False(string.IsNullOrWhiteSpace(loaded!.RevokedAtUtc));
    }

    [Fact]
    public async Task Revoke_by_token_sets_revoked()
    {
        // Scenario: revoca un refresh token cercandolo per valore in chiaro.
        // Risultato atteso: token trovato e marcato come revoked.
        var token = NewToken("userD");
        await _repo.CreateAsync(token, CancellationToken.None);

        await _repo.RevokeByTokenAsync(token.Token, "logout", CancellationToken.None);

        var loaded = await _repo.GetByTokenAsync(token.Token, CancellationToken.None);
        Assert.NotNull(loaded);
        Assert.False(string.IsNullOrWhiteSpace(loaded!.RevokedAtUtc));
        Assert.Equal("logout", loaded.RotationReason);
    }
}
