using System.Net;
using System.Net.Http.Json;
using Dapper;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace SecureAuthMinimalApi.Tests;

public class ChangePasswordExtendedTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    private const string DemoPassword = "123456789012";

    public ChangePasswordExtendedTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
    }

    private (WebApplicationFactory<Program> Factory, HttpClient Client, string DbPath) CreateFactory(IDictionary<string, string?>? extra = null)
    {
        var dbPath = Path.Combine(Path.GetTempPath(), $"changepw-tests-{Guid.NewGuid():N}.db");
        var factory = _factory.WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Development");
            builder.ConfigureAppConfiguration((context, configBuilder) =>
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
                        overrides[kv.Key] = kv.Value;
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

    [Fact]
    public async Task Change_password_missing_fields_returns_invalid_input()
    {
        var (factory, client, dbPath) = CreateFactory();
        try
        {
            var (cookie, csrf) = await LoginAsync(client);
            using var req = new HttpRequestMessage(HttpMethod.Post, "/me/password");
            req.Headers.Add("Cookie", cookie);
            req.Headers.Add("X-CSRF-Token", csrf);
            req.Content = JsonContent.Create(new { currentPassword = "", newPassword = "", confirmPassword = "" });

            var resp = await client.SendAsync(req);
            Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
            var payload = await resp.Content.ReadFromJsonAsync<ChangePasswordResponse>();
            Assert.NotNull(payload);
            Assert.Equal("invalid_input", payload!.Error);
            Assert.Contains("current_required", payload.Errors ?? Array.Empty<string>());
        }
        finally
        {
            factory.Dispose();
            client.Dispose();
            DeleteDb(dbPath);
        }
    }

    [Fact]
    public async Task Change_password_enforces_min_length_override()
    {
        var (factory, client, dbPath) = CreateFactory(new Dictionary<string, string?> { ["PasswordPolicy:MinLength"] = "20" });
        try
        {
            var (cookie, csrf) = await LoginAsync(client);
            using var req = new HttpRequestMessage(HttpMethod.Post, "/me/password");
            req.Headers.Add("Cookie", cookie);
            req.Headers.Add("X-CSRF-Token", csrf);
            req.Content = JsonContent.Create(new { currentPassword = DemoPassword, newPassword = "shortOne!", confirmPassword = "shortOne!" });

            var resp = await client.SendAsync(req);
            Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
            var payload = await resp.Content.ReadFromJsonAsync<ChangePasswordResponse>();
            Assert.NotNull(payload);
            Assert.Equal("password_policy_failed", payload!.Error);
            Assert.Contains("too_short", payload.Errors ?? Array.Empty<string>());
        }
        finally
        {
            factory.Dispose();
            client.Dispose();
            DeleteDb(dbPath);
        }
    }

    [Fact]
    public async Task Change_password_updates_hash_and_revokes_sessions()
    {
        var (factory, client, dbPath) = CreateFactory();
        try
        {
            var (cookie, csrf) = await LoginAsync(client);
            string beforeHash;
            await using (var db = new SqliteConnection($"Data Source={dbPath};Mode=ReadWriteCreate;Cache=Shared"))
            {
                await db.OpenAsync();
                beforeHash = await db.ExecuteScalarAsync<string>("SELECT password_hash FROM users WHERE username = 'demo';");
            }

            using (var req = new HttpRequestMessage(HttpMethod.Post, "/me/password"))
            {
                req.Headers.Add("Cookie", cookie);
                req.Headers.Add("X-CSRF-Token", csrf);
                req.Content = JsonContent.Create(new { currentPassword = DemoPassword, newPassword = "HashCheckPwd!123", confirmPassword = "HashCheckPwd!123" });
                var resp = await client.SendAsync(req);
                Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            }

            await using (var db = new SqliteConnection($"Data Source={dbPath};Mode=ReadWriteCreate;Cache=Shared"))
            {
                await db.OpenAsync();
                var afterHash = await db.ExecuteScalarAsync<string>("SELECT password_hash FROM users WHERE username = 'demo';");
                Assert.False(string.IsNullOrWhiteSpace(afterHash));
                Assert.NotEqual(beforeHash, afterHash);
                var sessions = await db.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM user_sessions WHERE revoked_at_utc IS NULL;");
                Assert.True(sessions <= 1, "Expected at most one active session after rotation");
            }
        }
        finally
        {
            factory.Dispose();
            client.Dispose();
            DeleteDb(dbPath);
        }
    }

    [Fact]
    public async Task Change_password_mismatch_returns_400()
    {
        var (factory, client, dbPath) = CreateFactory();
        try
        {
            var (cookie, csrf) = await LoginAsync(client);
            using var req = new HttpRequestMessage(HttpMethod.Post, "/me/password");
            req.Headers.Add("Cookie", cookie);
            req.Headers.Add("X-CSRF-Token", csrf);
            req.Content = JsonContent.Create(new { currentPassword = DemoPassword, newPassword = "NewPassword!123", confirmPassword = "DIFF" });

            var resp = await client.SendAsync(req);
            Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
            var payload = await resp.Content.ReadFromJsonAsync<ChangePasswordResponse>();
            Assert.NotNull(payload);
            Assert.False(payload!.Ok);
            Assert.Equal("password_mismatch", payload.Error);
        }
        finally
        {
            factory.Dispose();
            client.Dispose();
            DeleteDb(dbPath);
        }
    }

    [Fact]
    public async Task Change_password_without_csrf_returns_403()
    {
        var (factory, client, dbPath) = CreateFactory();
        try
        {
            var (cookie, _) = await LoginAsync(client);
            using var req = new HttpRequestMessage(HttpMethod.Post, "/me/password");
            req.Headers.Add("Cookie", cookie);
            req.Content = JsonContent.Create(new { currentPassword = DemoPassword, newPassword = "NewP@ss1", confirmPassword = "NewP@ss1" });

            var resp = await client.SendAsync(req);
            Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
        }
        finally
        {
            factory.Dispose();
            client.Dispose();
            DeleteDb(dbPath);
        }
    }

    [Fact]
    public async Task Change_password_policy_enforced_with_require_upper()
    {
        var (factory, client, dbPath) = CreateFactory(new Dictionary<string, string?> { ["PasswordPolicy:RequireUpper"] = "true" });
        try
        {
            var (cookie, csrf) = await LoginAsync(client);
            using var req = new HttpRequestMessage(HttpMethod.Post, "/me/password");
            req.Headers.Add("Cookie", cookie);
            req.Headers.Add("X-CSRF-Token", csrf);
            req.Content = JsonContent.Create(new { currentPassword = DemoPassword, newPassword = "loweronlypass1!", confirmPassword = "loweronlypass1!" });

            var resp = await client.SendAsync(req);
            Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
            var payload = await resp.Content.ReadFromJsonAsync<ChangePasswordResponse>();
            Assert.NotNull(payload);
            Assert.False(payload!.Ok);
            Assert.Equal("password_policy_failed", payload.Error);
            Assert.Contains("missing_upper", payload.Errors ?? Array.Empty<string>());
        }
        finally
        {
            factory.Dispose();
            client.Dispose();
            DeleteDb(dbPath);
        }
    }

    [Fact]
    public async Task Change_password_concurrent_requests_only_first_succeeds()
    {
        var (factory, client, dbPath) = CreateFactory();
        try
        {
            var (cookie, csrf) = await LoginAsync(client);

            async Task<HttpResponseMessage> ChangeAsync(string current, string next)
            {
                using var req = new HttpRequestMessage(HttpMethod.Post, "/me/password");
                req.Headers.Add("Cookie", cookie);
                req.Headers.Add("X-CSRF-Token", csrf);
                req.Content = JsonContent.Create(new { currentPassword = current, newPassword = next, confirmPassword = next });
                return await client.SendAsync(req);
            }

            var first = await ChangeAsync(DemoPassword, "NewPassword!123");
            var firstBody = await first.Content.ReadAsStringAsync();
            Assert.Equal(HttpStatusCode.OK, first.StatusCode);

            var second = await ChangeAsync(DemoPassword, "AnotherPassword!123");
            var secondBody = await second.Content.ReadAsStringAsync();
            Assert.Contains(second.StatusCode, new[] { HttpStatusCode.BadRequest, HttpStatusCode.Unauthorized });
            var payload = await second.Content.ReadFromJsonAsync<ChangePasswordResponse>();
            if (payload is not null)
            {
                Assert.True(payload.Error == "invalid_current_password" || payload.Error == "unauthorized");
            }
        }
        finally
        {
            factory.Dispose();
            client.Dispose();
            DeleteDb(dbPath);
        }
    }

    [Fact]
    public async Task Change_password_revokes_refresh_token()
    {
        var (factory, client, dbPath) = CreateFactory();
        try
        {
            // login con refresh
            var login = await client.PostAsJsonAsync("/login", new { Username = "demo", Password = DemoPassword, RememberMe = true });
            Assert.Equal(HttpStatusCode.OK, login.StatusCode);
            var cookie = login.Headers.GetValues("Set-Cookie").First(h => h.StartsWith("access_token")).Split(';', 2)[0];
            var refreshCookie = login.Headers.GetValues("Set-Cookie").First(h => h.StartsWith("refresh_token")).Split(';', 2)[0];
            var csrf = (await login.Content.ReadFromJsonAsync<LoginResponse>())!.CsrfToken!;

            // cambio password
            using (var req = new HttpRequestMessage(HttpMethod.Post, "/me/password"))
            {
                req.Headers.Add("Cookie", cookie);
                req.Headers.Add("X-CSRF-Token", csrf);
                req.Content = JsonContent.Create(new { currentPassword = DemoPassword, newPassword = "NewPassword!123", confirmPassword = "NewPassword!123" });
                var resp = await client.SendAsync(req);
                var body = await resp.Content.ReadAsStringAsync();
                Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            }

            // tenta refresh col vecchio cookie
            using var refreshReq = new HttpRequestMessage(HttpMethod.Post, "/refresh");
            refreshReq.Headers.Add("Cookie", refreshCookie);
            var refreshResp = await client.SendAsync(refreshReq);
            Assert.Equal(HttpStatusCode.Unauthorized, refreshResp.StatusCode);
        }
        finally
        {
            factory.Dispose();
            client.Dispose();
            DeleteDb(dbPath);
        }
    }

    private static async Task<(string Cookie, string Csrf)> LoginAsync(HttpClient client)
    {
        var login = await client.PostAsJsonAsync("/login", new { Username = "demo", Password = DemoPassword });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        var setCookie = login.Headers.GetValues("Set-Cookie").First(h => h.StartsWith("access_token"));
        var cookie = setCookie.Split(';', 2)[0];
        var csrf = (await login.Content.ReadFromJsonAsync<LoginResponse>())!.CsrfToken!;
        return (cookie, csrf);
    }

    private static void DeleteDb(string dbPath)
    {
        if (File.Exists(dbPath))
        {
            try { File.Delete(dbPath); } catch { }
        }
    }

    private sealed record ChangePasswordResponse(bool Ok, string? Error, IEnumerable<string>? Errors, string? CsrfToken);
    private sealed record LoginResponse(bool Ok, string? CsrfToken);
}
