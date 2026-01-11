using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Data.Sqlite;
using Xunit;

namespace SecureAuthMinimalApi.Tests;

public class LoginRateLimitTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public LoginRateLimitTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task Login_rate_limit_returns_429_after_threshold()
    {
        var (factory, client, dbPath) = CreateFactory(new Dictionary<string, string?>
        {
            ["Login:RateLimitRequests"] = "2",
            ["Login:RateLimitWindowMinutes"] = "1"
        });

        try
        {
            // 1° tentativo (credenziali sbagliate): 401
            var payload = new { username = "demo", password = "wrong" };
            var first = await client.PostAsJsonAsync("/login", payload);
            Assert.Equal(HttpStatusCode.Unauthorized, first.StatusCode);

            // 2° tentativo (credenziali sbagliate): 401
            var second = await client.PostAsJsonAsync("/login", payload);
            Assert.Equal(HttpStatusCode.Unauthorized, second.StatusCode);

            // 3° tentativo nella finestra: 429 per rate limit
            var third = await client.PostAsJsonAsync("/login", payload);
            Assert.Equal(HttpStatusCode.TooManyRequests, third.StatusCode);
        }
        finally
        {
            client.Dispose();
            factory.Dispose();
            SqliteConnection.ClearAllPools();
            if (File.Exists(dbPath))
            {
                File.Delete(dbPath);
            }
        }
    }

    private (WebApplicationFactory<Program> Factory, HttpClient Client, string DbPath) CreateFactory(IDictionary<string, string?>? extra = null)
    {
        var dbPath = Path.Combine(Path.GetTempPath(), $"login-rate-limit-{Guid.NewGuid():N}.db");
        var factory = _factory.WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Development");
            builder.ConfigureAppConfiguration((_, configBuilder) =>
            {
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
                    ["IdToken:IncludeEmail"] = "true"
                };

                if (extra is not null)
                {
                    foreach (var kv in extra)
                    {
                        overrides[kv.Key] = kv.Value;
                    }
                }

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
}
