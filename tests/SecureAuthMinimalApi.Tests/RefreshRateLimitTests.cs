using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Data.Sqlite;
using Xunit;

namespace SecureAuthMinimalApi.Tests;

public class RefreshRateLimitTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public RefreshRateLimitTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task Refresh_rate_limit_returns_429_after_threshold()
    {
        var (factory, client, dbPath) = CreateFactory(new Dictionary<string, string?>
        {
            ["Refresh:RateLimitRequests"] = "2",
            ["Refresh:RateLimitWindowMinutes"] = "1"
        });

        try
        {
            // Nessun cookie -> 401, ma conta per rate limit
            var first = await client.PostAsJsonAsync("/refresh", new { });
            Assert.Equal(HttpStatusCode.Unauthorized, first.StatusCode);

            var second = await client.PostAsJsonAsync("/refresh", new { });
            Assert.Equal(HttpStatusCode.Unauthorized, second.StatusCode);

            var third = await client.PostAsJsonAsync("/refresh", new { });
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
        var dbPath = Path.Combine(Path.GetTempPath(), $"refresh-rate-limit-{Guid.NewGuid():N}.db");
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
