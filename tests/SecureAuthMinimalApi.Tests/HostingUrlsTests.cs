using System;
using System.Linq;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace SecureAuthMinimalApi.Tests;

public class HostingUrlsTests
{
    [Fact]
    public void HostingUrls_FromConfiguration_AreAppliedToServerAddresses()
    {
        // Scenario: config imposta Hosting:Urls a un endpoint specifico.
        // Risultato atteso: l'indirizzo atteso appare in IServerAddressesFeature.
        const string expectedUrl = "https://localhost:52899";
        var dbPath = Path.Combine(Path.GetTempPath(), $"hosting-urls-{Guid.NewGuid():N}.db");

        using var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("Hosting:Urls:0", expectedUrl);
            builder.UseSetting("ConnectionStrings:Sqlite", $"Data Source={dbPath};Mode=ReadWriteCreate;Cache=Shared");
            builder.UseSetting("Cookie:RequireSecure", "false");
            builder.UseSetting("Jwt:SecretKey", "TEST_SECRET_KEY_AT_LEAST_32_CHARACTERS_LONG__");
            builder.UseSetting("Jwt:Issuer", "TestIssuer");
            builder.UseSetting("Jwt:Audience", "TestAudience");
            builder.UseSetting("Jwt:AccessTokenMinutes", "60");
        });

        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            HandleCookies = false,
            AllowAutoRedirect = false
        });

        var server = factory.Services.GetRequiredService<IServer>();
        var addresses = server.Features.Get<IServerAddressesFeature>()?.Addresses ?? Array.Empty<string>();

        Assert.NotEmpty(addresses);
        Assert.Contains(addresses, url => string.Equals(expectedUrl, url.TrimEnd('/'), StringComparison.OrdinalIgnoreCase));
    }
}
