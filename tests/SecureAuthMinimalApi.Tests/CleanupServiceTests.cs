using System.Diagnostics;
using Dapper;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using Xunit;
using Xunit.Sdk;

namespace SecureAuthMinimalApi.Tests;

/// <summary>
/// Test di integrazione per il background service di cleanup.
/// </summary>
public class CleanupServiceTests
{
    private static (WebApplicationFactory<Program> Factory, HttpClient Client, string DbPath) CreateFactory(
        IDictionary<string, string?>? extraConfig = null)
    {
        var dbPath = Path.Combine(Path.GetTempPath(), $"cleanup-tests-{Guid.NewGuid():N}.db");
        var overrides = new Dictionary<string, string?>
        {
            ["ConnectionStrings:Sqlite"] = $"Data Source={dbPath};Mode=ReadWriteCreate;Cache=Shared",
            ["Cookie:RequireSecure"] = "false",
            ["Jwt:SecretKey"] = "TEST_SECRET_KEY_AT_LEAST_32_CHARACTERS_LONG__",
            ["Jwt:Issuer"] = "TestIssuer",
            ["Jwt:Audience"] = "TestAudience",
            ["Jwt:AccessTokenMinutes"] = "60",
            ["IdToken:Issuer"] = "TestIdIssuer",
            ["IdToken:Audience"] = "TestIdAudience",
            ["IdToken:Secret"] = "TEST_ID_TOKEN_SECRET_AT_LEAST_32_CHARS_LONG___",
            ["IdToken:IncludeEmail"] = "true",
            ["Cleanup:Enabled"] = "true",
            ["Cleanup:IntervalSeconds"] = "1",
            ["Cleanup:BatchSize"] = "50",
            ["Cleanup:MaxIterationsPerRun"] = "3"
        };

        if (extraConfig is not null)
        {
            foreach (var kv in extraConfig)
            {
                overrides[kv.Key] = kv.Value;
            }
        }

        var factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.UseEnvironment("Development");
                builder.ConfigureAppConfiguration((context, configBuilder) =>
                {
                    configBuilder.AddInMemoryCollection(overrides);
                });
            });

        var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            HandleCookies = false,
            AllowAutoRedirect = false
        });

        return (factory, client, dbPath);
    }

    [Fact]
    public async Task Cleanup_removes_expired_records()
    {
        var (factory, client, dbPath) = CreateFactory();
        try
        {
            await SeedExpiredRecordsAsync(dbPath);

            await WaitUntilAsync(async () =>
            {
                var sessions = await CountAsync(dbPath, "user_sessions");
                var refresh = await CountAsync(dbPath, "refresh_tokens");
                var challenges = await CountAsync(dbPath, "mfa_challenges");
                return sessions == 0 && refresh == 0 && challenges == 0;
            }, TimeSpan.FromSeconds(5));
        }
        finally
        {
            client.Dispose();
            factory.Dispose();
            TryDeleteDb(dbPath);
        }
    }

    [Fact]
    public async Task Cleanup_disabled_does_not_remove_records()
    {
        var (factory, client, dbPath) = CreateFactory(new Dictionary<string, string?>
        {
            ["Cleanup:Enabled"] = "false"
        });
        try
        {
            await SeedExpiredRecordsAsync(dbPath);
            await Task.Delay(TimeSpan.FromSeconds(2));

            Assert.Equal(1, await CountAsync(dbPath, "user_sessions"));
            Assert.Equal(1, await CountAsync(dbPath, "refresh_tokens"));
            Assert.Equal(1, await CountAsync(dbPath, "mfa_challenges"));
        }
        finally
        {
            client.Dispose();
            factory.Dispose();
            TryDeleteDb(dbPath);
        }
    }

    [Fact]
    public async Task Cleanup_batches_when_limited_iterations()
    {
        var (factory, client, dbPath) = CreateFactory(new Dictionary<string, string?>
        {
            ["Cleanup:BatchSize"] = "1",
            ["Cleanup:MaxIterationsPerRun"] = "1",
            ["Cleanup:IntervalSeconds"] = "1"
        });
        try
        {
            await SeedExpiredRefreshTokensAsync(dbPath, 3);

            await Task.Delay(TimeSpan.FromSeconds(1.2));
            var remainingAfterFirstRun = await CountAsync(dbPath, "refresh_tokens");
            Assert.InRange(remainingAfterFirstRun, 1, 3);
            Assert.True(remainingAfterFirstRun < 3);

            await WaitUntilAsync(async () => await CountAsync(dbPath, "refresh_tokens") == 0, TimeSpan.FromSeconds(5));
        }
        finally
        {
            client.Dispose();
            factory.Dispose();
            TryDeleteDb(dbPath);
        }
    }

    [Fact]
    public async Task Cleanup_keeps_valid_records()
    {
        var (factory, client, dbPath) = CreateFactory(new Dictionary<string, string?>
        {
            ["Cleanup:IntervalSeconds"] = "1"
        });
        try
        {
            await SeedValidRecordsAsync(dbPath);
            await Task.Delay(TimeSpan.FromSeconds(2));

            Assert.Equal(1, await CountAsync(dbPath, "user_sessions"));
            Assert.Equal(1, await CountAsync(dbPath, "refresh_tokens"));
            Assert.Equal(1, await CountAsync(dbPath, "mfa_challenges"));
        }
        finally
        {
            client.Dispose();
            factory.Dispose();
            TryDeleteDb(dbPath);
        }
    }

    private static async Task SeedExpiredRecordsAsync(string dbPath)
    {
        var past = DateTime.UtcNow.AddMinutes(-10).ToString("O");
        await using var conn = new SqliteConnection($"Data Source={dbPath};Mode=ReadWriteCreate;Cache=Shared");
        await conn.OpenAsync();
        await conn.ExecuteAsync(
            @"INSERT INTO user_sessions (session_id, user_id, created_at_utc, expires_at_utc, revoked_at_utc, user_data_json, csrf_token, last_seen_utc)
              VALUES (@id, @user, @created, @exp, @revoked, @data, @csrf, @lastSeen);",
            new
            {
                id = "sess-expired",
                user = "user1",
                created = past,
                exp = past,
                revoked = past,
                data = "{}",
                csrf = "csrf",
                lastSeen = past
            });
        await conn.ExecuteAsync(
            @"INSERT INTO refresh_tokens (id, user_id, session_id, token_hash, created_at_utc, expires_at_utc, revoked_at_utc, user_agent, client_ip, device_id, device_label, rotation_parent_id, rotation_reason)
              VALUES (@id, @user, @session, @hash, @created, @exp, @revoked, NULL, NULL, NULL, NULL, NULL, 'revoked');",
            new
            {
                id = "rt-expired",
                user = "user1",
                session = "sess-expired",
                hash = "hash-expired",
                created = past,
                exp = past,
                revoked = past
            });
        await conn.ExecuteAsync(
            @"INSERT INTO mfa_challenges (id, user_id, created_at_utc, expires_at_utc, used_at_utc, user_agent, client_ip, attempt_count)
              VALUES (@id, @user, @created, @exp, @used, NULL, NULL, 0);",
            new
            {
                id = "mfa-expired",
                user = "user1",
                created = past,
                exp = past,
                used = past
            });
    }

    private static async Task SeedExpiredRefreshTokensAsync(string dbPath, int count)
    {
        var past = DateTime.UtcNow.AddMinutes(-5).ToString("O");
        await using var conn = new SqliteConnection($"Data Source={dbPath};Mode=ReadWriteCreate;Cache=Shared");
        await conn.OpenAsync();
        for (var i = 0; i < count; i++)
        {
            await conn.ExecuteAsync(
                @"INSERT INTO refresh_tokens (id, user_id, session_id, token_hash, created_at_utc, expires_at_utc, revoked_at_utc, user_agent, client_ip, device_id, device_label, rotation_parent_id, rotation_reason)
                  VALUES (@id, @user, @session, @hash, @created, @exp, @revoked, NULL, NULL, NULL, NULL, NULL, 'cleanup-test');",
                new
                {
                    id = $"rt-expired-{i}",
                    user = "user1",
                    session = "sess-batch",
                    hash = $"hash-expired-{i}",
                    created = past,
                    exp = past,
                    revoked = past
                });
        }
    }

    private static async Task SeedValidRecordsAsync(string dbPath)
    {
        var now = DateTime.UtcNow;
        var future = now.AddMinutes(30).ToString("O");
        var created = now.ToString("O");
        await using var conn = new SqliteConnection($"Data Source={dbPath};Mode=ReadWriteCreate;Cache=Shared");
        await conn.OpenAsync();
        await conn.ExecuteAsync(
            @"INSERT INTO user_sessions (session_id, user_id, created_at_utc, expires_at_utc, revoked_at_utc, user_data_json, csrf_token, last_seen_utc)
              VALUES (@id, @user, @created, @exp, NULL, @data, @csrf, @lastSeen);",
            new
            {
                id = "sess-valid",
                user = "user2",
                created,
                exp = future,
                data = "{}",
                csrf = "csrf",
                lastSeen = created
            });
        await conn.ExecuteAsync(
            @"INSERT INTO refresh_tokens (id, user_id, session_id, token_hash, created_at_utc, expires_at_utc, revoked_at_utc, user_agent, client_ip, device_id, device_label, rotation_parent_id, rotation_reason)
              VALUES (@id, @user, @session, @hash, @created, @exp, NULL, NULL, NULL, NULL, NULL, NULL, NULL);",
            new
            {
                id = "rt-valid",
                user = "user2",
                session = "sess-valid",
                hash = "hash-valid",
                created,
                exp = future
            });
        await conn.ExecuteAsync(
            @"INSERT INTO mfa_challenges (id, user_id, created_at_utc, expires_at_utc, used_at_utc, user_agent, client_ip, attempt_count)
              VALUES (@id, @user, @created, @exp, NULL, NULL, NULL, 0);",
            new
            {
                id = "mfa-valid",
                user = "user2",
                created,
                exp = future
            });
    }

    private static async Task<int> CountAsync(string dbPath, string table)
    {
        await using var conn = new SqliteConnection($"Data Source={dbPath};Mode=ReadWriteCreate;Cache=Shared");
        await conn.OpenAsync();
        return await conn.ExecuteScalarAsync<int>($"SELECT COUNT(1) FROM {table};");
    }

    private static async Task WaitUntilAsync(Func<Task<bool>> condition, TimeSpan timeout)
    {
        var sw = Stopwatch.StartNew();
        while (sw.Elapsed < timeout)
        {
            if (await condition())
            {
                return;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(150));
        }

        throw new XunitException("Timeout in attesa del cleanup");
    }

    private static void TryDeleteDb(string dbPath)
    {
        try
        {
            if (File.Exists(dbPath))
            {
                File.Delete(dbPath);
            }
        }
        catch (IOException)
        {
            // best effort
        }
    }
}
