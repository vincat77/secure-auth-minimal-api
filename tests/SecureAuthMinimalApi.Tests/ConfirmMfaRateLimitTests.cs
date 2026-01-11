using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace SecureAuthMinimalApi.Tests;

public class ConfirmMfaRateLimitTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public ConfirmMfaRateLimitTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task Confirm_mfa_rate_limit_returns_429_after_threshold()
    {
        var (factory, client, dbPath, challengeId, totpCode) = await CreateFactoryAsync(new Dictionary<string, string?>
        {
            ["ConfirmMfa:RateLimitRequests"] = "1",
            ["ConfirmMfa:RateLimitWindowMinutes"] = "1"
        });

        try
        {
            // 1° conferma: attesa 200/401/403 a seconda del codice (qui useremo codice errato -> 401)
            var first = await client.PostAsJsonAsync("/login/confirm-mfa", new { challengeId, totpCode });
            Assert.NotEqual(HttpStatusCode.TooManyRequests, first.StatusCode);

            // 2° conferma nella finestra: deve essere 429 per rate limit
            var second = await client.PostAsJsonAsync("/login/confirm-mfa", new { challengeId, totpCode });
            Assert.Equal(HttpStatusCode.TooManyRequests, second.StatusCode);
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

    private async Task<(WebApplicationFactory<Program> Factory, HttpClient Client, string DbPath, string ChallengeId, string Totp)> CreateFactoryAsync(IDictionary<string, string?>? extra = null)
    {
        var dbPath = Path.Combine(Path.GetTempPath(), $"confirm-mfa-rate-limit-{Guid.NewGuid():N}.db");

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
                    ["IdToken:IncludeEmail"] = "true",
                    ["EmailConfirmation:Required"] = "false"
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
            HandleCookies = true,
            AllowAutoRedirect = false
        });

        // registra utente con MFA
        var username = $"u-{Guid.NewGuid():N}";
        var password = "Password123!";
        var reg = await client.PostAsJsonAsync("/register", new
        {
            username,
            password,
            confirmPassword = password,
            email = $"test-{Guid.NewGuid():N}@example.com"
        });
        reg.EnsureSuccessStatusCode();

        // setup MFA
        var login1 = await client.PostAsJsonAsync("/login", new { username, password });
        login1.EnsureSuccessStatusCode();
        var login1Json = await login1.Content.ReadFromJsonAsync<JsonElement>();
        var csrf = login1Json.GetProperty("csrfToken").GetString();
        client.DefaultRequestHeaders.Add("X-CSRF-Token", csrf);
        var setup = await client.PostAsync("/mfa/setup", null);
        setup.EnsureSuccessStatusCode();
        var setupJson = await setup.Content.ReadFromJsonAsync<JsonElement>();

        // logout per forzare nuovo login con MFA
        var logout = await client.PostAsync("/logout", null);
        logout.EnsureSuccessStatusCode();
        client.DefaultRequestHeaders.Remove("X-CSRF-Token");

        // login -> mfa_required
        var login2 = await client.PostAsJsonAsync("/login", new { username, password });
        var loginJson = await login2.Content.ReadFromJsonAsync<JsonElement>();
        var challengeId = loginJson.GetProperty("challengeId").GetString()!;

        // codice TOTP invalido per test rate-limit
        var totpCode = "000000"; // deliberatamente errato

        return (factory, client, dbPath, challengeId, totpCode);
    }
}
