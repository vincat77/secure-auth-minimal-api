using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace SecureAuthMinimalApi.Tests;

/// <summary>
/// Smoke test per verificare che l'app parta con Serilog e risponda a /health.
/// </summary>
public class SerilogSmokeTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public SerilogSmokeTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("ConnectionStrings:Sqlite", $"Data Source={Path.Combine(Path.GetTempPath(), $"serilog-smoke-{Guid.NewGuid():N}.db")};Mode=ReadWriteCreate;Cache=Shared");
            builder.UseSetting("Cookie:RequireSecure", "false");
            builder.UseSetting("Jwt:SecretKey", "TEST_SECRET_KEY_AT_LEAST_32_CHARACTERS_LONG__");
            builder.UseSetting("Jwt:Issuer", "TestIssuer");
            builder.UseSetting("Jwt:Audience", "TestAudience");
            builder.UseSetting("Jwt:AccessTokenMinutes", "60");
        });
    }

    [Fact]
    public async Task Health_endpoint_works_with_serilog_config()
    {
        // Scenario: avvia l'app con configurazione Serilog e chiama GET /health per verificare che il logging non interferisca.
        // Risultato atteso: /health risponde 200.
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            HandleCookies = false,
            AllowAutoRedirect = false
        });

        var resp = await client.GetAsync("/health");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }
}
