using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Data.Sqlite;
using Xunit;

namespace SecureAuthMinimalApi.Tests;

public class ConfirmEmailRateLimitTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public ConfirmEmailRateLimitTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task Confirm_email_rate_limit_returns_429_after_threshold()
    {
        var (factory, client, dbPath) = await CreateFactoryAsync(new Dictionary<string, string?>
        {
            ["ConfirmEmail:RateLimitRequests"] = "2",
            ["ConfirmEmail:RateLimitWindowMinutes"] = "1"
        });

        try
        {
            var payload = new { token = "bad-token" };

            var first = await client.PostAsJsonAsync("/confirm-email", payload);
            Assert.Equal(HttpStatusCode.BadRequest, first.StatusCode);

            var second = await client.PostAsJsonAsync("/confirm-email", payload);
            Assert.Equal(HttpStatusCode.BadRequest, second.StatusCode);

            var third = await client.PostAsJsonAsync("/confirm-email", payload);
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

    private async Task<(WebApplicationFactory<Program> Factory, HttpClient Client, string DbPath)> CreateFactoryAsync(IDictionary<string, string?>? extra = null)
    {
        var dbPath = Path.Combine(Path.GetTempPath(), $"confirm-rate-limit-{Guid.NewGuid():N}.db");

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

        // Nessuna preparazione necessaria per token invalido
        await Task.CompletedTask;
        return (factory, client, dbPath);
    }
}
