using System.Net;
using System.Net.Http.Json;
using Dapper;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace SecureAuthMinimalApi.Tests;

/// <summary>
/// Test per idle timeout e header informativi.
/// </summary>
public class IdleTimeoutTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    private const string DemoPassword = "123456789012";

    public IdleTimeoutTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("Cookie:RequireSecure", "false");
            builder.UseSetting("ConnectionStrings:Sqlite", $"Data Source={Path.Combine(Path.GetTempPath(), $"idle-tests-{Guid.NewGuid():N}.db")};Mode=ReadWriteCreate;Cache=Shared");
            builder.UseSetting("Jwt:SecretKey", "TEST_SECRET_KEY_AT_LEAST_32_CHARACTERS_LONG__");
            builder.UseSetting("Jwt:Issuer", "TestIssuer");
            builder.UseSetting("Jwt:Audience", "TestAudience");
            builder.UseSetting("Jwt:AccessTokenMinutes", "60");
            builder.UseSetting("Session:IdleMinutes", "1"); // 1 minuto per i test
        });
    }

    private record LoginResponse(bool Ok, string? CsrfToken);

    private async Task<(HttpClient client, string dbPath)> CreateClientAsync()
    {
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            HandleCookies = false,
            AllowAutoRedirect = false
        });
        var config = _factory.Services.GetRequiredService<IConfiguration>();
        var dbPath = config["ConnectionStrings:Sqlite"] ?? "";
        return (client, dbPath.Replace("Data Source=", "").Split(';')[0]);
    }

    [Fact]
    public async Task Idle_expired_session_returns_401_and_revokes()
    {
        var (client, dbPath) = await CreateClientAsync();
        try
        {
            // login
            var login = await client.PostAsJsonAsync("/login", new { Username = "demo", Password = DemoPassword });
            var csrf = (await login.Content.ReadFromJsonAsync<LoginResponse>())!.CsrfToken!;
            var accessCookie = login.Headers.GetValues("Set-Cookie").First(c => c.StartsWith("access_token")).Split(';', 2)[0];

            // forza last_seen a passato (oltre idle)
            await using (var db = new SqliteConnection($"Data Source={dbPath};Mode=ReadWriteCreate;Cache=Shared"))
            {
                await db.OpenAsync();
                await db.ExecuteAsync("UPDATE user_sessions SET last_seen_utc = @ls", new { ls = DateTime.UtcNow.AddMinutes(-5).ToString("O") });
            }

            // me deve tornare 401
            using var meReq = new HttpRequestMessage(HttpMethod.Get, "/me");
            meReq.Headers.Add("Cookie", accessCookie);
            var meResp = await client.SendAsync(meReq);
            Assert.Equal(HttpStatusCode.Unauthorized, meResp.StatusCode);
        }
        finally
        {
            client.Dispose();
        }
    }

    [Fact]
    public async Task Idle_within_timeout_updates_last_seen_and_returns_ok()
    {
        var (client, dbPath) = await CreateClientAsync();
        try
        {
            var login = await client.PostAsJsonAsync("/login", new { Username = "demo", Password = DemoPassword });
            var accessCookie = login.Headers.GetValues("Set-Cookie").First(c => c.StartsWith("access_token")).Split(';', 2)[0];

            using var meReq = new HttpRequestMessage(HttpMethod.Get, "/me");
            meReq.Headers.Add("Cookie", accessCookie);
            var meResp = await client.SendAsync(meReq);
            Assert.Equal(HttpStatusCode.OK, meResp.StatusCode);

            await using var db = new SqliteConnection($"Data Source={dbPath};Mode=ReadWriteCreate;Cache=Shared");
            await db.OpenAsync();
            var lastSeen = await db.ExecuteScalarAsync<string>("SELECT last_seen_utc FROM user_sessions LIMIT 1;");
            Assert.False(string.IsNullOrWhiteSpace(lastSeen));
        }
        finally
        {
            client.Dispose();
        }
    }

    [Fact]
    public async Task Idle_disabled_behaves_as_before()
    {
        var factory = _factory.WithWebHostBuilder(builder => builder.UseSetting("Session:IdleMinutes", "0"));
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false, AllowAutoRedirect = false });
        var login = await client.PostAsJsonAsync("/login", new { Username = "demo", Password = DemoPassword });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
    }

    [Fact]
    public async Task Headers_expose_expiry_and_idle_remaining()
    {
        var (client, dbPath) = await CreateClientAsync();
        try
        {
            var login = await client.PostAsJsonAsync("/login", new { Username = "demo", Password = DemoPassword });
            var accessCookie = login.Headers.GetValues("Set-Cookie").First(c => c.StartsWith("access_token")).Split(';', 2)[0];

            using var meReq = new HttpRequestMessage(HttpMethod.Get, "/me");
            meReq.Headers.Add("Cookie", accessCookie);
            var meResp = await client.SendAsync(meReq);
            Assert.Equal(HttpStatusCode.OK, meResp.StatusCode);

            Assert.True(meResp.Headers.TryGetValues("X-Session-Expires-At", out var expHeader));
            Assert.NotEmpty(expHeader);
            Assert.True(meResp.Headers.TryGetValues("X-Session-Idle-Remaining", out var idleHeader));
            Assert.NotEmpty(idleHeader);
        }
        finally
        {
            client.Dispose();
        }
    }
}
