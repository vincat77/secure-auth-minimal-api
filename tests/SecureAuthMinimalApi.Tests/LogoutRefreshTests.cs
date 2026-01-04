using System.Net;
using System.Net.Http.Json;
using Dapper;
using Microsoft.Data.Sqlite;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using System.Text.Json;
using Microsoft.Extensions.Configuration;

namespace SecureAuthMinimalApi.Tests;

/// <summary>
/// Test per revoca refresh in logout e logout-all.
/// </summary>
public class LogoutRefreshTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    private const string DemoPassword = "123456789012";

    public LogoutRefreshTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("Cookie:RequireSecure", "false");
            builder.UseSetting("ConnectionStrings:Sqlite", $"Data Source={Path.Combine(Path.GetTempPath(), $"logout-tests-{Guid.NewGuid():N}.db")};Mode=ReadWriteCreate;Cache=Shared");
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
    public async Task Logout_revokes_refresh_token()
    {
        var (client, dbPath) = await CreateClientAsync();
        try
        {
            var login = await client.PostAsJsonAsync("/login", new { Username = "demo", Password = DemoPassword, RememberMe = true });
            Assert.Equal(HttpStatusCode.OK, login.StatusCode);
            var csrf = (await login.Content.ReadFromJsonAsync<LoginResponse>())!.CsrfToken!;
            var setCookies = login.Headers.GetValues("Set-Cookie").ToList();
            var accessCookie = setCookies.First(c => c.StartsWith("access_token", StringComparison.OrdinalIgnoreCase)).Split(';', 2)[0];
            var refreshCookie = setCookies.First(c => c.StartsWith("refresh_token", StringComparison.OrdinalIgnoreCase)).Split(';', 2)[0];

            using var logoutReq = new HttpRequestMessage(HttpMethod.Post, "/logout");
            logoutReq.Headers.Add("Cookie", $"{accessCookie}; {refreshCookie}");
            logoutReq.Headers.Add("X-CSRF-Token", csrf);
            var logout = await client.SendAsync(logoutReq);
            Assert.Equal(HttpStatusCode.OK, logout.StatusCode);

            await using var db = new SqliteConnection($"Data Source={dbPath};Mode=ReadWriteCreate;Cache=Shared");
            await db.OpenAsync();
            var revoked = await db.ExecuteScalarAsync<string>("SELECT revoked_at_utc FROM refresh_tokens ORDER BY created_at_utc DESC LIMIT 1;");
            Assert.False(string.IsNullOrWhiteSpace(revoked));
        }
        finally
        {
            client.Dispose();
        }
    }
}
