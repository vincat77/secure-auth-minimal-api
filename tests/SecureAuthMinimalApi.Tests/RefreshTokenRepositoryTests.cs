using Dapper;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using SecureAuthMinimalApi.Data;
using SecureAuthMinimalApi.Models;
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

    public Task InitializeAsync()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), $"refresh-tests-{Guid.NewGuid():N}.db");
        _config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:Sqlite"] = $"Data Source={_dbPath};Mode=ReadWriteCreate;Cache=Shared"
            })
            .Build();

        DbInitializer.EnsureCreated(_config);
        _repo = new RefreshTokenRepository(_config);
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
        var token = NewToken("user1");
        await _repo.CreateAsync(token, CancellationToken.None);

        var loaded = await _repo.GetByTokenAsync(token.Token, CancellationToken.None);
        Assert.NotNull(loaded);
        Assert.Equal(token.Id, loaded!.Id);
        Assert.Equal(token.UserId, loaded.UserId);
        Assert.Equal(token.Token, loaded.Token);
        Assert.Null(loaded.RevokedAtUtc);
    }

    [Fact]
    public async Task Rotate_revokes_old_and_inserts_new()
    {
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
    }

    [Fact]
    public async Task Revoke_all_for_user_revokes_only_target_user()
    {
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
        var token = NewToken("userD");
        await _repo.CreateAsync(token, CancellationToken.None);

        await _repo.RevokeByTokenAsync(token.Token, "logout", CancellationToken.None);

        var loaded = await _repo.GetByTokenAsync(token.Token, CancellationToken.None);
        Assert.NotNull(loaded);
        Assert.False(string.IsNullOrWhiteSpace(loaded!.RevokedAtUtc));
        Assert.Equal("logout", loaded.RotationReason);
    }
}
