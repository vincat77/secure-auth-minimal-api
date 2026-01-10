using System.Net;
using System.Net.Http.Json;
using Dapper;
using Microsoft.Data.Sqlite;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace SecureAuthMinimalApi.Tests;

/// <summary>
/// Test per l'endpoint /logout-all che revoca tutti i refresh token dell'utente.
/// </summary>
public class LogoutAllTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    private const string DemoPassword = "123456789012";

    public LogoutAllTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("Cookie:RequireSecure", "false");
            builder.UseSetting("ConnectionStrings:Sqlite", $"Data Source={Path.Combine(Path.GetTempPath(), $"logoutall-tests-{Guid.NewGuid():N}.db")};Mode=ReadWriteCreate;Cache=Shared");
            builder.UseSetting("Jwt:SecretKey", "TEST_SECRET_KEY_AT_LEAST_32_CHARACTERS_LONG__");
            builder.UseSetting("Jwt:Issuer", "TestIssuer");
            builder.UseSetting("Jwt:Audience", "TestAudience");
            builder.UseSetting("Jwt:AccessTokenMinutes", "60");
            builder.UseSetting("RememberMe:CookieName", "refresh_token");
            builder.UseSetting("RememberMe:Path", "/refresh");
            builder.UseSetting("RememberMe:SameSite", "Strict");
            builder.UseSetting("RememberMe:Days", "7");
        });
    }

    private record LoginResponse(bool Ok, string? CsrfToken, bool? RememberIssued);

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
    public async Task Logout_all_revokes_all_refresh_for_user()
    {
        // Scenario: utente con più refresh token attivi invoca POST /logout-all per revocarli tutti.
        // Risultato atteso: tutti i refresh token dell'utente risultano revocati e non più usabili.
        var (client, dbPath) = await CreateClientAsync();
        try
        {
            // login con remember per ottenere refresh
            var login = await client.PostAsJsonAsync("/login", new { Username = "demo", Password = DemoPassword, RememberMe = true });
            Assert.Equal(HttpStatusCode.OK, login.StatusCode);
            var csrf = (await login.Content.ReadFromJsonAsync<LoginResponse>())!.CsrfToken!;
            var cookies = login.Headers.GetValues("Set-Cookie").ToList();
            var accessCookie = cookies.First(c => c.StartsWith("access_token")).Split(';', 2)[0];
            var refreshCookie = cookies.First(c => c.StartsWith("refresh_token")).Split(';', 2)[0];

            // seconda sessione per lo stesso utente con altro refresh
            var login2 = await client.PostAsJsonAsync("/login", new { Username = "demo", Password = DemoPassword, RememberMe = true });
            var refreshCookie2 = login2.Headers.GetValues("Set-Cookie").First(c => c.StartsWith("refresh_token")).Split(';', 2)[0];

            using var logoutAllReq = new HttpRequestMessage(HttpMethod.Post, "/logout-all");
            logoutAllReq.Headers.Add("Cookie", $"{accessCookie}; {refreshCookie}");
            logoutAllReq.Headers.Add("X-CSRF-Token", csrf);
            var logoutAll = await client.SendAsync(logoutAllReq);
            Assert.Equal(HttpStatusCode.OK, logoutAll.StatusCode);

            await using var db = new SqliteConnection($"Data Source={dbPath};Mode=ReadWriteCreate;Cache=Shared");
            await db.OpenAsync();
            var revoked = await db.QueryAsync<string>("SELECT revoked_at_utc FROM refresh_tokens WHERE user_id = 'demo-user';");
            Assert.All(revoked, r => Assert.False(string.IsNullOrWhiteSpace(r)));
        }
        finally
        {
            client.Dispose();
        }
    }
}
