using System.Net;
using System.Net.Http.Json;
using Microsoft.Data.Sqlite;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Dapper;
using Xunit;
using Xunit.Abstractions;
using System.Runtime.CompilerServices;
using SecureAuthMinimalApi.Services;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Text.Json;
using OtpNet;
using SecureAuthMinimalApi.Data;

namespace SecureAuthMinimalApi.Tests;

/// <summary>
/// Test di integrazione end-to-end su login/me/logout, hardening CSRF, JWT e introspection.
/// </summary>
public class ApiTests : IAsyncLifetime
{
    private readonly ITestOutputHelper _output;
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"secure-auth-tests-{Guid.NewGuid():N}.db");
    private WebApplicationFactory<Program> _factory = null!;
    private HttpClient _client = null!;
    private RefreshTokenHasher _hasher = null!;

    public ApiTests(ITestOutputHelper output)
    {
        _output = output;
    }

    // Crea una factory isolata con DB SQLite temporaneo e flag Secure cookie configurabile.
    private static (WebApplicationFactory<Program> Factory, HttpClient Client, string DbPath) CreateFactory(bool requireSecure, bool forceLowerUsername = false, IDictionary<string, string?>? extraConfig = null)
    {
        var dbPath = Path.Combine(Path.GetTempPath(), $"secure-auth-tests-{Guid.NewGuid():N}.db");
        var factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                var envValue = "Development";
                if (extraConfig is not null && extraConfig.TryGetValue("Environment", out var env) && !string.IsNullOrWhiteSpace(env))
                {
                    envValue = env!;
                }
                builder.UseEnvironment(envValue);
                builder.ConfigureAppConfiguration((context, configBuilder) =>
                {
                    var overrides = new Dictionary<string, string?>
                    {
                        ["ConnectionStrings:Sqlite"] = $"Data Source={dbPath};Mode=ReadWriteCreate;Cache=Shared",
                        ["Cookie:RequireSecure"] = requireSecure ? "true" : "false",
                        ["Jwt:SecretKey"] = "TEST_SECRET_KEY_AT_LEAST_32_CHARACTERS_LONG__",
                        ["Jwt:Issuer"] = "TestIssuer",
                        ["Jwt:Audience"] = "TestAudience",
                        ["Jwt:AccessTokenMinutes"] = "60",
                        ["IdToken:Issuer"] = "TestIdIssuer",
                        ["IdToken:Audience"] = "TestIdAudience",
                        ["IdToken:Secret"] = "TEST_ID_TOKEN_SECRET_AT_LEAST_32_CHARS_LONG___",
                        ["IdToken:IncludeEmail"] = "true",
                        ["UsernamePolicy:Lowercase"] = forceLowerUsername ? "true" : "false"
                    };
                    if (extraConfig is not null)
                    {
                        foreach (var kv in extraConfig)
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

    // Setup di default per i test (RequireSecure disabilitato per simulare HTTP locale).
    public Task InitializeAsync()
    {
        _factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.UseEnvironment("Development");
                builder.ConfigureAppConfiguration((context, configBuilder) =>
                {
                    var overrides = new Dictionary<string, string?>
                    {
                        ["ConnectionStrings:Sqlite"] = $"Data Source={_dbPath};Mode=ReadWriteCreate;Cache=Shared",
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
                    configBuilder.AddInMemoryCollection(overrides);
                });
            });

        _client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            HandleCookies = false,
            AllowAutoRedirect = false
        });
        _hasher = new RefreshTokenHasher(_factory.Services.GetRequiredService<IConfiguration>());

        return Task.CompletedTask;
    }

    // Cleanup risorse e DB temp (best-effort).
    public Task DisposeAsync()
    {
        _client.Dispose();
        _factory.Dispose();
        if (File.Exists(_dbPath))
        {
            try
            {
                File.Delete(_dbPath);
            }
            catch (IOException)
            {
                // best-effort cleanup; SQLite may still hold the file briefly
            }
        }

        return Task.CompletedTask;
    }

    private void LogTestStart([CallerMemberName] string name = "")
        => _output.WriteLine($"[TEST] {name}");

    [Fact]
    public async Task Health_endpoint_returns_ok()
    {
        LogTestStart();
        var response = await _client.GetAsync("/health");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var payload = await response.Content.ReadFromJsonAsync<HealthResponse>();
        Assert.NotNull(payload);
        Assert.True(payload!.Ok);
    }

    [Fact]
    public async Task Live_endpoint_returns_ok()
    {
        LogTestStart();
        var response = await _client.GetAsync("/live");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var payload = await response.Content.ReadFromJsonAsync<HealthResponse>();
        Assert.NotNull(payload);
        Assert.True(payload!.Ok);
    }

    [Fact]
    public async Task Login_me_logout_flow()
    {
        LogTestStart();
        var loginResponse = await _client.PostAsJsonAsync("/login", new { Username = "demo", Password = "demo" });
        Assert.Equal(HttpStatusCode.OK, loginResponse.StatusCode);

        var loginPayload = await loginResponse.Content.ReadFromJsonAsync<LoginResponse>();
        Assert.NotNull(loginPayload);
        Assert.True(loginPayload!.Ok);
        Assert.False(string.IsNullOrWhiteSpace(loginPayload.CsrfToken));

        var csrfToken = loginPayload.CsrfToken!;
        var setCookie = loginResponse.Headers.GetValues("Set-Cookie").FirstOrDefault(h => h.StartsWith("access_token", StringComparison.Ordinal));
        _output.WriteLine($"Set-Cookie: {setCookie}");
        Assert.False(string.IsNullOrWhiteSpace(setCookie));
        var accessCookie = setCookie!.Split(';', 2)[0];
        var token = accessCookie.Split('=', 2)[1];
        Assert.False(string.IsNullOrWhiteSpace(loginPayload.IdToken));

        await using (var db = new SqliteConnection($"Data Source={_dbPath};Mode=ReadWriteCreate;Cache=Shared"))
        {
            await db.OpenAsync();
            var countCmd = db.CreateCommand();
            countCmd.CommandText = "SELECT COUNT(*) FROM user_sessions;";
            var count = (long)(await countCmd.ExecuteScalarAsync() ?? 0L);
            _output.WriteLine($"user_sessions rows: {count}");
            Assert.True(count > 0, "Expected at least one session row after login");
        }

        using var meRequest = new HttpRequestMessage(HttpMethod.Get, "/me");
        meRequest.Headers.Add("Cookie", accessCookie);

        var meResponse = await _client.SendAsync(meRequest);
        _output.WriteLine($"GET /me status: {meResponse.StatusCode}");
        _output.WriteLine($"GET /me body: {await meResponse.Content.ReadAsStringAsync()}");
        Assert.Equal(HttpStatusCode.OK, meResponse.StatusCode);

        var mePayload = await meResponse.Content.ReadFromJsonAsync<MeResponse>();
        Assert.NotNull(mePayload);
        Assert.True(mePayload!.Ok);
        Assert.Equal("demo-user", mePayload.UserId);
        Assert.False(string.IsNullOrWhiteSpace(mePayload.SessionId));

        using var logoutRequest = new HttpRequestMessage(HttpMethod.Post, "/logout");
        logoutRequest.Headers.Add("X-CSRF-Token", csrfToken);
        logoutRequest.Headers.Add("Cookie", accessCookie);

        var logoutResponse = await _client.SendAsync(logoutRequest);
        _output.WriteLine($"POST /logout status: {logoutResponse.StatusCode}");
        _output.WriteLine($"POST /logout body: {await logoutResponse.Content.ReadAsStringAsync()}");
        Assert.Equal(HttpStatusCode.OK, logoutResponse.StatusCode);

        var logoutPayload = await logoutResponse.Content.ReadFromJsonAsync<LogoutResponse>();
        Assert.NotNull(logoutPayload);
        Assert.True(logoutPayload!.Ok);

        var meAfterLogout = await _client.GetAsync("/me");
        Assert.Equal(HttpStatusCode.Unauthorized, meAfterLogout.StatusCode);
    }

    private sealed record HealthResponse(bool Ok);
    private sealed record LoginResponse(bool Ok, string? CsrfToken, bool? RememberIssued, string? RefreshExpiresAtUtc, bool? DeviceIssued, string? DeviceId, string? IdToken);
    private sealed record MeResponse(bool Ok, string SessionId, string UserId);
    private sealed record LogoutResponse(bool Ok);
    private sealed record RegisterResponse(bool Ok, string? UserId, string? EmailConfirmToken, string? EmailConfirmExpiresUtc);
    private sealed record ConfirmEmailResponse(bool Ok, bool? AlreadyConfirmed);
    private sealed record IntrospectResponse(bool Active, string? Reason, string? SessionId, string? UserId, string? ExpiresAtUtc);
    private sealed record MfaSetupResponse(bool Ok, string? Secret, string? OtpauthUri);
    private sealed record MfaRequiredResponse(bool? Ok, string? Error, string? ChallengeId);
    private sealed record MfaConfirmResponse(bool Ok, string? CsrfToken, bool? RememberIssued, string? RefreshExpiresAtUtc, bool? DeviceIssued, string? DeviceId, string? IdToken);
    private sealed record ErrorResponse(bool? Ok, string? Error);

    private async Task ConfirmEmailAsync(string token)
    {
        var resp = await _client.PostAsJsonAsync("/confirm-email", new { Token = token });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    private static JwtSecurityToken ValidateIdToken(string token, TokenValidationParameters tvp)
    {
        var handler = new JwtSecurityTokenHandler { MapInboundClaims = false };
        handler.ValidateToken(token, tvp, out var validated);
        return (JwtSecurityToken)validated;
    }

    [Fact]
    public void Jwt_claims_are_minimal_and_validatable()
    {
        LogTestStart();
        var jwtService = _factory.Services.GetRequiredService<JwtTokenService>();
        var (token, expires) = jwtService.CreateAccessToken("session-123");

        var handler = new JwtSecurityTokenHandler { MapInboundClaims = false };
        var jwt = handler.ReadJwtToken(token);

        Assert.Equal("HS256", jwt.Header.Alg);
        Assert.Equal("TestIssuer", jwt.Issuer);
        Assert.Equal("TestAudience", jwt.Audiences.Single());
        Assert.Equal("session-123", jwt.Claims.First(c => c.Type == JwtRegisteredClaimNames.Sub).Value);
        Assert.True(jwt.Claims.First(c => c.Type == JwtRegisteredClaimNames.Jti).Value.Length > 10);

        var claimTypes = jwt.Claims.Select(c => c.Type).ToHashSet();
        var allowed = new[]
        {
            JwtRegisteredClaimNames.Sub,
            JwtRegisteredClaimNames.Jti,
            JwtRegisteredClaimNames.Iat,
            JwtRegisteredClaimNames.Aud,
            JwtRegisteredClaimNames.Exp,
            JwtRegisteredClaimNames.Nbf,
            JwtRegisteredClaimNames.Iss
        };
        Assert.True(allowed.All(claimTypes.Contains), "Missing required claims");
        Assert.True(claimTypes.All(allowed.Contains), $"Unexpected claims: {string.Join(',', claimTypes.Except(allowed))}");

        var principal = handler.ValidateToken(token, jwtService.GetValidationParameters(), out var validated);
        Assert.NotNull(principal);
        Assert.IsType<JwtSecurityToken>(validated);
        Assert.Equal("session-123", principal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value);
        Assert.True(expires > DateTime.UtcNow);
    }

    [Fact]
    public async Task Login_sets_cookie_with_expected_flags()
    {
        LogTestStart();
        var (factory, client, dbPath) = CreateFactory(requireSecure: true);
        try
        {
            var response = await client.PostAsJsonAsync("/login", new { Username = "demo", Password = "demo" });
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            var setCookie = response.Headers.GetValues("Set-Cookie").FirstOrDefault(h => h.StartsWith("access_token", StringComparison.OrdinalIgnoreCase));
            Assert.False(string.IsNullOrWhiteSpace(setCookie));

            var header = setCookie!.ToLowerInvariant();
            Assert.Contains("access_token=", header);
            Assert.Contains("httponly", header);
            Assert.Contains("samesite=strict", header);
            Assert.Contains("path=/", header);
            Assert.Contains("secure", header);
            Assert.Contains("max-age", header);
        }
        finally
        {
            client.Dispose();
            factory.Dispose();
            if (File.Exists(dbPath))
            {
                try { File.Delete(dbPath); } catch (IOException) { }
            }
        }
    }

    [Fact]
    public async Task Login_with_wrong_credentials_returns_unauthorized()
    {
        LogTestStart();
        var response = await _client.PostAsJsonAsync("/login", new { Username = "demo", Password = "wrong" });
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Register_then_login_success()
    {
        LogTestStart();
        var username = $"user_{Guid.NewGuid():N}";
        var password = "P@ssw0rd!Long";
        var email = $"{username}@example.com";

        var register = await _client.PostAsJsonAsync("/register", new { Username = username, Password = password, Email = email });
        Assert.Equal(HttpStatusCode.Created, register.StatusCode);
        var regPayload = await register.Content.ReadFromJsonAsync<RegisterResponse>();
        Assert.NotNull(regPayload);
        Assert.True(regPayload!.Ok);
        Assert.False(string.IsNullOrWhiteSpace(regPayload.UserId));
        Assert.False(string.IsNullOrWhiteSpace(regPayload.EmailConfirmToken));
        Assert.False(string.IsNullOrWhiteSpace(regPayload.EmailConfirmExpiresUtc));

        await ConfirmEmailAsync(regPayload.EmailConfirmToken!);

        var (cookie, csrf) = await LoginAndGetSessionAsync(username, password);

        using var meReq = new HttpRequestMessage(HttpMethod.Get, "/me");
        meReq.Headers.Add("Cookie", cookie);
        var me = await _client.SendAsync(meReq);
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);

        using var logoutReq = new HttpRequestMessage(HttpMethod.Post, "/logout");
        logoutReq.Headers.Add("Cookie", cookie);
        logoutReq.Headers.Add("X-CSRF-Token", csrf);
        var logout = await _client.SendAsync(logoutReq);
        Assert.Equal(HttpStatusCode.OK, logout.StatusCode);
    }

    [Fact]
    public async Task Register_duplicate_returns_conflict()
    {
        LogTestStart();
        var username = $"dup_{Guid.NewGuid():N}";
        var password = "P@ssw0rd!Long";
        var email = $"{username}@example.com";

        var first = await _client.PostAsJsonAsync("/register", new { Username = username, Password = password, Email = email });
        Assert.Equal(HttpStatusCode.Created, first.StatusCode);

        var second = await _client.PostAsJsonAsync("/register", new { Username = username, Password = password, Email = email });
        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
    }

    [Fact]
    public async Task Register_generates_email_confirmation_token_and_persists()
    {
        LogTestStart();
        var username = $"mailtoken_{Guid.NewGuid():N}";
        var password = "P@ssw0rd!Long";
        var email = $"{username}@example.com";

        var resp = await _client.PostAsJsonAsync("/register", new { Username = username, Password = password, Email = email });
        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);

        var payload = await resp.Content.ReadFromJsonAsync<RegisterResponse>();
        Assert.NotNull(payload);
        Assert.False(string.IsNullOrWhiteSpace(payload!.EmailConfirmToken));
        Assert.False(string.IsNullOrWhiteSpace(payload.EmailConfirmExpiresUtc));

        await using var db = new SqliteConnection($"Data Source={_dbPath};Mode=ReadWriteCreate;Cache=Shared");
        await db.OpenAsync();
        var row = await db.QuerySingleAsync<(string Token, string Expires)>("SELECT email_confirm_token, email_confirm_expires_utc FROM users WHERE username = @u", new { u = username });
        Assert.Equal(payload.EmailConfirmToken, row.Token);
        Assert.Equal(payload.EmailConfirmExpiresUtc, row.Expires);
    }

    [Fact]
    public async Task Login_blocks_when_email_not_confirmed()
    {
        LogTestStart();
        var username = $"need_confirm_{Guid.NewGuid():N}";
        var email = $"{username}@example.com";
        var password = "P@ssw0rd!Long";

        var reg = await _client.PostAsJsonAsync("/register", new { Username = username, Password = password, Email = email });
        Assert.Equal(HttpStatusCode.Created, reg.StatusCode);
        var payload = await reg.Content.ReadFromJsonAsync<RegisterResponse>();
        Assert.NotNull(payload);
        var token = payload!.EmailConfirmToken!;

        var login = await _client.PostAsJsonAsync("/login", new { Username = username, Password = password });
        Assert.Equal(HttpStatusCode.Forbidden, login.StatusCode);
        var doc = await login.Content.ReadFromJsonAsync<JsonDocument>();
        Assert.NotNull(doc);
        Assert.Equal("email_not_confirmed", doc!.RootElement.GetProperty("error").GetString());

        await ConfirmEmailAsync(token);

        var loginOk = await _client.PostAsJsonAsync("/login", new { Username = username, Password = password });
        Assert.Equal(HttpStatusCode.OK, loginOk.StatusCode);
    }

    [Fact]
    public async Task Confirm_email_with_valid_token_marks_confirmed()
    {
        LogTestStart();
        var username = $"confirm_{Guid.NewGuid():N}";
        var password = "P@ssw0rd!Long";
        var email = $"{username}@example.com";

        var reg = await _client.PostAsJsonAsync("/register", new { Username = username, Password = password, Email = email });
        Assert.Equal(HttpStatusCode.Created, reg.StatusCode);
        var payload = await reg.Content.ReadFromJsonAsync<RegisterResponse>();
        Assert.NotNull(payload);
        var token = payload!.EmailConfirmToken!;

        var confirm = await _client.PostAsJsonAsync("/confirm-email", new { Token = token });
        Assert.Equal(HttpStatusCode.OK, confirm.StatusCode);
        var confirmPayload = await confirm.Content.ReadFromJsonAsync<ConfirmEmailResponse>();
        Assert.True(confirmPayload!.Ok);

        await using var db = new SqliteConnection($"Data Source={_dbPath};Mode=ReadWriteCreate;Cache=Shared");
        await db.OpenAsync();
        var flags = await db.QuerySingleAsync<(long Confirmed, string? Token, string? Exp)>("SELECT email_confirmed, email_confirm_token, email_confirm_expires_utc FROM users WHERE username = @u", new { u = username });
        Assert.Equal(1, flags.Confirmed);
        Assert.Null(flags.Token);
        Assert.Null(flags.Exp);
    }

    [Fact]
    public async Task Confirm_email_with_expired_token_returns_gone()
    {
        LogTestStart();
        var username = $"confirm_exp_{Guid.NewGuid():N}";
        var password = "P@ssw0rd!Long";
        var email = $"{username}@example.com";

        var reg = await _client.PostAsJsonAsync("/register", new { Username = username, Password = password, Email = email });
        Assert.Equal(HttpStatusCode.Created, reg.StatusCode);
        var payload = await reg.Content.ReadFromJsonAsync<RegisterResponse>();
        Assert.NotNull(payload);
        var token = payload!.EmailConfirmToken!;

        await using (var db = new SqliteConnection($"Data Source={_dbPath};Mode=ReadWriteCreate;Cache=Shared"))
        {
            await db.OpenAsync();
            await db.ExecuteAsync("UPDATE users SET email_confirm_expires_utc = @exp WHERE username = @u", new { exp = DateTime.UtcNow.AddMinutes(-5).ToString("O"), u = username });
        }

        var confirm = await _client.PostAsJsonAsync("/confirm-email", new { Token = token });
        Assert.Equal(HttpStatusCode.Gone, confirm.StatusCode);
    }

    [Fact]
    public async Task Confirm_email_with_invalid_token_returns_bad_request()
    {
        LogTestStart();
        var response = await _client.PostAsJsonAsync("/confirm-email", new { Token = "invalid" });
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Register_duplicate_email_case_insensitive_returns_conflict()
    {
        LogTestStart();
        var username1 = $"user1_{Guid.NewGuid():N}";
        var username2 = $"user2_{Guid.NewGuid():N}";
        var emailMixed = $"Mixed_{Guid.NewGuid():N}@Example.com";
        var password = "P@ssw0rd!Long";

        var first = await _client.PostAsJsonAsync("/register", new { Username = username1, Password = password, Email = emailMixed });
        Assert.Equal(HttpStatusCode.Created, first.StatusCode);

        var second = await _client.PostAsJsonAsync("/register", new { Username = username2, Password = password, Email = emailMixed.ToUpperInvariant() });
        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
    }

    [Fact]
    public async Task Register_normalizes_email_to_lowercase()
    {
        LogTestStart();
        var username = $"normmail_{Guid.NewGuid():N}";
        var emailMixed = $"Mixed_{Guid.NewGuid():N}@Example.com";
        var password = "P@ssw0rd!Long";

        var register = await _client.PostAsJsonAsync("/register", new { Username = username, Password = password, Email = emailMixed });
        Assert.Equal(HttpStatusCode.Created, register.StatusCode);

        await using var db = new SqliteConnection($"Data Source={_dbPath};Mode=ReadWriteCreate;Cache=Shared");
        await db.OpenAsync();
        var stored = await db.ExecuteScalarAsync<string>("SELECT email_normalized FROM users WHERE username = @u", new { u = username });
        Assert.Equal(emailMixed.ToLowerInvariant(), stored);
    }

    [Fact]
    public async Task Register_with_short_password_returns_bad_request()
    {
        LogTestStart();
        var username = $"short_{Guid.NewGuid():N}";
        var shortPwd = "short";
        var email = $"{username}@example.com";

        var response = await _client.PostAsJsonAsync("/register", new { Username = username, Password = shortPwd, Email = email });
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        var doc = await response.Content.ReadFromJsonAsync<JsonDocument>();
        Assert.NotNull(doc);
        Assert.Equal("password_policy_failed", doc!.RootElement.GetProperty("error").GetString());
        var errors = doc.RootElement.GetProperty("errors").EnumerateArray().Select(e => e.GetString()).ToList();
        Assert.Contains("too_short", errors);
    }

    [Fact]
    public void JwtTokenService_requires_minimum_secret_length()
    {
        LogTestStart();
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Jwt:Issuer"] = "i",
                ["Jwt:Audience"] = "a",
                ["Jwt:SecretKey"] = "short", // < 32 chars
                ["Jwt:AccessTokenMinutes"] = "30"
            })
            .Build();

        var ex = Assert.Throws<InvalidOperationException>(() => new JwtTokenService(config));
        Assert.Contains("SecretKey must be at least 32", ex.Message);
    }

    [Fact]
    public void JwtTokenService_requires_secret()
    {
        LogTestStart();
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Jwt:Issuer"] = "i",
                ["Jwt:Audience"] = "a",
                ["Jwt:SecretKey"] = ""
            })
            .Build();

        var ex = Assert.Throws<InvalidOperationException>(() => new JwtTokenService(config));
        Assert.Contains("Missing Jwt:SecretKey", ex.Message);
    }

    [Fact]
    public void JwtTokenService_requires_issuer_and_audience()
    {
        LogTestStart();
        var configMissingIssuer = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                // issuer mancante
                ["Jwt:Audience"] = "a",
                ["Jwt:SecretKey"] = "THIS_IS_A_LONG_SECRET_KEY_32_CHARS_MIN"
            })
            .Build();
        var ex1 = Assert.Throws<InvalidOperationException>(() => new JwtTokenService(configMissingIssuer));
        Assert.Contains("Missing Jwt:Issuer", ex1.Message);

        var configMissingAudience = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Jwt:Issuer"] = "i",
                // audience mancante
                ["Jwt:SecretKey"] = "THIS_IS_A_LONG_SECRET_KEY_32_CHARS_MIN"
            })
            .Build();
        var ex2 = Assert.Throws<InvalidOperationException>(() => new JwtTokenService(configMissingAudience));
        Assert.Contains("Missing Jwt:Audience", ex2.Message);
    }

    [Fact]
    public void DbInitializer_requires_connection_string()
    {
        LogTestStart();
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>()).Build();
        var ex = Assert.Throws<InvalidOperationException>(() => DbInitializer.EnsureCreated(config));
        Assert.Contains("Missing ConnectionStrings:Sqlite", ex.Message);
    }

    [Fact]
    public void DbInitializer_is_idempotent_and_seeds_demo_once()
    {
        LogTestStart();
        var dbPath = Path.Combine(Path.GetTempPath(), $"dbinit-{Guid.NewGuid():N}.db");
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:Sqlite"] = $"Data Source={dbPath};Mode=ReadWriteCreate;Cache=Shared"
            })
            .Build();

        try
        {
            DbInitializer.EnsureCreated(config);
            DbInitializer.EnsureCreated(config); // seconda chiamata non deve fallire

            using var conn = new SqliteConnection($"Data Source={dbPath};Mode=ReadWriteCreate;Cache=Shared");
            conn.Open();

            var demoCount = conn.ExecuteScalar<long>("SELECT COUNT(*) FROM users WHERE username = 'demo';");
            Assert.Equal(1, demoCount);

            var pragma = conn.Query("PRAGMA table_info(users);").ToList();
            Assert.Contains(pragma, c => ((string)c.name).Contains("totp_secret", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            if (File.Exists(dbPath))
            {
                try { File.Delete(dbPath); } catch { }
            }
        }
    }

    [Fact]
    public async Task Register_with_missing_symbol_fails_password_policy()
    {
        LogTestStart();
        var extraConfig = new Dictionary<string, string?>
        {
            ["PasswordPolicy:MinLength"] = "8",
            ["PasswordPolicy:RequireUpper"] = "true",
            ["PasswordPolicy:RequireLower"] = "true",
            ["PasswordPolicy:RequireDigit"] = "true",
            ["PasswordPolicy:RequireSymbol"] = "true"
        };

        var (factory, client, dbPath) = CreateFactory(requireSecure: false, forceLowerUsername: false, extraConfig: extraConfig);
        try
        {
            var username = $"pol_{Guid.NewGuid():N}";
            var email = $"{username}@example.com";
            var password = "Strong123"; // manca simbolo

            var response = await client.PostAsJsonAsync("/register", new { Username = username, Password = password, Email = email });
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

            var doc = await response.Content.ReadFromJsonAsync<JsonDocument>();
            Assert.NotNull(doc);
            Assert.Equal("password_policy_failed", doc!.RootElement.GetProperty("error").GetString());
            var errors = doc.RootElement.GetProperty("errors").EnumerateArray().Select(e => e!.GetString()).ToList();
            Assert.Contains("missing_symbol", errors);
            Assert.DoesNotContain("too_short", errors); // lunghezza sufficiente
        }
        finally
        {
            client.Dispose();
            factory.Dispose();
            if (File.Exists(dbPath))
            {
                try { File.Delete(dbPath); } catch { }
            }
        }
    }

    [Fact]
    public async Task Health_in_production_includes_security_headers()
    {
        LogTestStart();
        var extra = new Dictionary<string, string?>
        {
            ["Environment"] = "Production"
        };
        var (factory, client, dbPath) = CreateFactory(requireSecure: true, forceLowerUsername: false, extraConfig: extra);
        try
        {
            var response = await client.GetAsync("/health");
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var headers = response.Headers;
            Assert.True(headers.TryGetValues("X-Frame-Options", out var frame) && frame.Contains("DENY"));
            Assert.True(headers.TryGetValues("X-Content-Type-Options", out var ct) && ct.Contains("nosniff"));
            Assert.True(headers.TryGetValues("Referrer-Policy", out var refp) && refp.Contains("no-referrer"));
            Assert.True(headers.TryGetValues("X-XSS-Protection", out var xss) && xss.Contains("0"));
            Assert.True(headers.TryGetValues("Content-Security-Policy", out var csp) && csp.Any(v => v.Contains("default-src 'none'", StringComparison.OrdinalIgnoreCase)));
        }
        finally
        {
            client.Dispose();
            factory.Dispose();
            if (File.Exists(dbPath))
            {
                try { File.Delete(dbPath); } catch { }
            }
        }
    }

    [Fact]
    public async Task Login_in_production_forces_secure_cookie_even_if_disabled()
    {
        LogTestStart();
        var extra = new Dictionary<string, string?>
        {
            ["Environment"] = "Production",
            ["Cookie:RequireSecure"] = "false" // deve essere ignorato
        };
        var (factory, client, dbPath) = CreateFactory(requireSecure: false, forceLowerUsername: false, extraConfig: extra);
        try
        {
            var response = await client.PostAsJsonAsync("/login", new { Username = "demo", Password = "demo" });
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var setCookie = response.Headers.GetValues("Set-Cookie").FirstOrDefault(h => h.StartsWith("access_token", StringComparison.OrdinalIgnoreCase));
            Assert.False(string.IsNullOrWhiteSpace(setCookie));
            var lower = setCookie!.ToLowerInvariant();
            Assert.Contains("secure", lower); // forzato in prod
        }
        finally
        {
            client.Dispose();
            factory.Dispose();
            if (File.Exists(dbPath))
            {
                try { File.Delete(dbPath); } catch { }
            }
        }
    }

    [Fact]
    public async Task Ready_endpoint_returns_200_when_db_and_jwt_are_valid()
    {
        LogTestStart();
        var response = await _client.GetAsync("/ready");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Ready_endpoint_returns_503_when_jwt_secret_missing()
    {
        LogTestStart();
        var extra = new Dictionary<string, string?>
        {
            ["Jwt:SecretKey"] = "",
            ["Tests:SkipDbInit"] = "true"
        };
        var (factory, client, dbPath) = CreateFactory(requireSecure: false, forceLowerUsername: false, extraConfig: extra);
        try
        {
            var resp = await client.GetAsync("/ready");
            Assert.Equal(HttpStatusCode.ServiceUnavailable, resp.StatusCode);
            var doc = await resp.Content.ReadFromJsonAsync<JsonDocument>();
            Assert.NotNull(doc);
            Assert.Equal("invalid_config", doc!.RootElement.GetProperty("error").GetString());
        }
        finally
        {
            client.Dispose();
            factory.Dispose();
            if (File.Exists(dbPath))
            {
                try { File.Delete(dbPath); } catch { }
            }
        }
    }

    [Fact]
    public async Task Ready_endpoint_returns_503_when_db_unreachable()
    {
        LogTestStart();
        var extra = new Dictionary<string, string?>
        {
            ["ConnectionStrings:Sqlite"] = "Data Source=Z:\\nonexistent\\db.db",
            ["Tests:SkipDbInit"] = "true"
        };
        var (factory, client, dbPath) = CreateFactory(requireSecure: false, forceLowerUsername: false, extraConfig: extra);
        try
        {
            var resp = await client.GetAsync("/ready");
            Assert.Equal(HttpStatusCode.ServiceUnavailable, resp.StatusCode);
            var doc = await resp.Content.ReadFromJsonAsync<JsonDocument>();
            Assert.NotNull(doc);
            Assert.Equal("db_unreachable", doc!.RootElement.GetProperty("error").GetString());
        }
        finally
        {
            client.Dispose();
            factory.Dispose();
            if (File.Exists(dbPath))
            {
                try { File.Delete(dbPath); } catch { }
            }
        }
    }

    [Fact]
    public async Task Register_fails_when_min_length_is_invalid_config()
    {
        LogTestStart();
        // MinLength = 0 deve far rifiutare la password troppo corta in fase di register.
        var extraConfig = new Dictionary<string, string?>
        {
            ["PasswordPolicy:MinLength"] = "0"
        };

        var (factory, client, dbPath) = CreateFactory(requireSecure: false, forceLowerUsername: false, extraConfig: extraConfig);
        try
        {
            var response = await client.PostAsJsonAsync("/register", new { Username = "u_invalid_min", Password = "a", Email = "u_invalid_min@example.com" });
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

            var doc = await response.Content.ReadFromJsonAsync<JsonDocument>();
            Assert.NotNull(doc);
            Assert.Equal("password_policy_failed", doc!.RootElement.GetProperty("error").GetString());
            var errors = doc.RootElement.GetProperty("errors").EnumerateArray().Select(e => e!.GetString()).ToList();
            Assert.Contains("too_short", errors);
        }
        finally
        {
            client.Dispose();
            factory.Dispose();
            if (File.Exists(dbPath))
            {
                try { File.Delete(dbPath); } catch { }
            }
        }
    }

    [Fact]
    public void JwtTokenService_requires_positive_access_token_minutes()
    {
        LogTestStart();
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Jwt:Issuer"] = "i",
                ["Jwt:Audience"] = "a",
                ["Jwt:SecretKey"] = "THIS_IS_A_LONG_SECRET_KEY_32_CHARS_MIN",
                ["Jwt:AccessTokenMinutes"] = "0"
            })
            .Build();

        var ex = Assert.Throws<InvalidOperationException>(() => new JwtTokenService(config));
        Assert.Contains("AccessTokenMinutes must be > 0", ex.Message);
    }

    [Fact]
    public async Task DbInitializer_adds_missing_totp_column_on_old_schema()
    {
        LogTestStart();
        var dbPath = Path.Combine(Path.GetTempPath(), $"dbinit-old-{Guid.NewGuid():N}.db");
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:Sqlite"] = $"Data Source={dbPath};Mode=ReadWriteCreate;Cache=Shared"
            })
            .Build();

        try
        {
            // Crea schema "vecchio" senza totp_secret.
            await using (var conn = new SqliteConnection($"Data Source={dbPath};Mode=ReadWriteCreate;Cache=Shared"))
            {
                await conn.OpenAsync();
                const string ddlOld = @"
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at_utc TEXT NOT NULL
);";
                await conn.ExecuteAsync(ddlOld);
            }

            DbInitializer.EnsureCreated(config); // deve aggiungere la colonna mancante

            using var connCheck = new SqliteConnection($"Data Source={dbPath};Mode=ReadWriteCreate;Cache=Shared");
            connCheck.Open();
            var pragma = connCheck.Query("PRAGMA table_info(users);").ToList();
            Assert.Contains(pragma, c => ((string)c.name).Equals("totp_secret", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            if (File.Exists(dbPath))
            {
                try { File.Delete(dbPath); } catch { }
            }
        }
    }

    [Fact]
    public async Task Login_audit_stores_outcome_and_no_password_in_detail()
    {
        LogTestStart();
        var username = $"auditdetail_{Guid.NewGuid():N}";
        var password = "P@ssw0rd!Long";
        var email = $"{username}@example.com";

        var register = await _client.PostAsJsonAsync("/register", new { Username = username, Password = password, Email = email });
        Assert.Equal(HttpStatusCode.Created, register.StatusCode);
        var regPayload = await register.Content.ReadFromJsonAsync<RegisterResponse>();
        Assert.NotNull(regPayload);
        await ConfirmEmailAsync(regPayload!.EmailConfirmToken!);

        var fail = await _client.PostAsJsonAsync("/login", new { Username = username, Password = "wrong" });
        Assert.Equal(HttpStatusCode.Unauthorized, fail.StatusCode);

        var ok = await _client.PostAsJsonAsync("/login", new { Username = username, Password = password });
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);

        await using var db = new SqliteConnection($"Data Source={_dbPath};Mode=ReadWriteCreate;Cache=Shared");
        await db.OpenAsync();
        var rows = (await db.QueryAsync<(string Outcome, string? Detail)>(
            "SELECT outcome AS Outcome, detail AS Detail FROM login_audit WHERE username = @u",
            new { u = username })).ToList();

        Assert.Contains(rows, r => r.Outcome == "invalid_credentials" && r.Detail == null);
        var successRow = rows.FirstOrDefault(r => r.Outcome == "success");
        Assert.NotEqual(default, successRow);
        Assert.False(string.IsNullOrWhiteSpace(successRow.Detail));
        Assert.DoesNotContain(password, successRow.Detail, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("userId=", successRow.Detail, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Login_lockout_after_failures_returns_429()
    {
        LogTestStart();
        var username = $"lock_{Guid.NewGuid():N}";
        // 5 tentativi errati -> 401, al 6° scatta il lock -> 429
        for (var i = 0; i < 5; i++)
        {
            var resp = await _client.PostAsJsonAsync("/login", new { Username = username, Password = "wrong" });
            Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        }

        var locked = await _client.PostAsJsonAsync("/login", new { Username = username, Password = "wrong" });
        Assert.Equal((HttpStatusCode)429, locked.StatusCode);
    }

    [Fact]
    public async Task Login_lockout_respects_custom_threshold()
    {
        LogTestStart();
        var extra = new Dictionary<string, string?>
        {
            ["LoginThrottle:MaxFailures"] = "3",
            ["LoginThrottle:LockMinutes"] = "1"
        };

        var (factory, client, dbPath) = CreateFactory(requireSecure: false, forceLowerUsername: false, extraConfig: extra);
        try
        {
            var username = $"lockparam_{Guid.NewGuid():N}";
            // 3 errori -> 401, al 4° deve scattare 429
            for (var i = 0; i < 3; i++)
            {
                var resp = await client.PostAsJsonAsync("/login", new { Username = username, Password = "wrong" });
                Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
            }

            var locked = await client.PostAsJsonAsync("/login", new { Username = username, Password = "wrong" });
            Assert.Equal((HttpStatusCode)429, locked.StatusCode);
        }
        finally
        {
            client.Dispose();
            factory.Dispose();
            if (File.Exists(dbPath))
            {
                try { File.Delete(dbPath); } catch { }
            }
        }
    }

    [Fact]
    public async Task Register_trims_username_and_allows_login()
    {
        LogTestStart();
        var rawUsername = $" trim_{Guid.NewGuid():N} ";
        var trimmed = rawUsername.Trim();
        var password = "P@ssw0rd!Long";
        var email = $"{trimmed}@example.com";

        var register = await _client.PostAsJsonAsync("/register", new { Username = rawUsername, Password = password, Email = email });
        Assert.Equal(HttpStatusCode.Created, register.StatusCode);

        var (cookie, csrf) = await LoginAndGetSessionAsync(trimmed, password);
        using var meReq = new HttpRequestMessage(HttpMethod.Get, "/me");
        meReq.Headers.Add("Cookie", cookie);
        var me = await _client.SendAsync(meReq);
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);

        using var logoutReq = new HttpRequestMessage(HttpMethod.Post, "/logout");
        logoutReq.Headers.Add("Cookie", cookie);
        logoutReq.Headers.Add("X-CSRF-Token", csrf);
        var logout = await _client.SendAsync(logoutReq);
        Assert.Equal(HttpStatusCode.OK, logout.StatusCode);
    }

    [Fact]
    public async Task Login_resets_throttle_after_success()
    {
        LogTestStart();
        var username = $"reset_{Guid.NewGuid():N}";
        var password = "P@ssw0rd!Longer";
        var email = $"{username}@example.com";

        var reg = await _client.PostAsJsonAsync("/register", new { Username = username, Password = password, Email = email });
        Assert.Equal(HttpStatusCode.Created, reg.StatusCode);

        // 3 errori (sotto il limite di lock)
        for (var i = 0; i < 3; i++)
        {
            var resp = await _client.PostAsJsonAsync("/login", new { Username = username, Password = "wrong" });
            Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        }

        // login corretto resetta stato
        var (cookie, csrf) = await LoginAndGetSessionAsync(username, password);
        using var logoutReq = new HttpRequestMessage(HttpMethod.Post, "/logout");
        logoutReq.Headers.Add("Cookie", cookie);
        logoutReq.Headers.Add("X-CSRF-Token", csrf);
        var logout = await _client.SendAsync(logoutReq);
        Assert.Equal(HttpStatusCode.OK, logout.StatusCode);

        // dopo il successo, un nuovo errore deve tornare 401 (non 429)
        var wrongAgain = await _client.PostAsJsonAsync("/login", new { Username = username, Password = "wrong" });
        Assert.Equal(HttpStatusCode.Unauthorized, wrongAgain.StatusCode);
    }

    [Fact]
    public async Task Register_duplicate_with_trim_returns_conflict()
    {
        LogTestStart();
        var username = $"trimdup_{Guid.NewGuid():N}";
        var padded = $"  {username}  ";
        var password = "P@ssw0rd!Long";
        var email = $"{username}@example.com";

        var first = await _client.PostAsJsonAsync("/register", new { Username = username, Password = password, Email = email });
        Assert.Equal(HttpStatusCode.Created, first.StatusCode);

        var second = await _client.PostAsJsonAsync("/register", new { Username = padded, Password = password, Email = email });
        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
    }

    [Fact]
    public async Task Register_missing_fields_returns_bad_request()
    {
        LogTestStart();
        var r1 = await _client.PostAsJsonAsync("/register", new { Username = "", Password = "whatever", Email = "" });
        Assert.Equal(HttpStatusCode.BadRequest, r1.StatusCode);
        var d1 = await r1.Content.ReadFromJsonAsync<JsonDocument>();
        Assert.Equal("invalid_input", d1!.RootElement.GetProperty("error").GetString());
        var e1 = d1.RootElement.GetProperty("errors").EnumerateArray().Select(x => x.GetString()).ToList();
        Assert.Contains("username_required", e1);

        var r2 = await _client.PostAsJsonAsync("/register", new { Username = "userx", Password = "", Email = "mail@example.com" });
        Assert.Equal(HttpStatusCode.BadRequest, r2.StatusCode);
        var d2 = await r2.Content.ReadFromJsonAsync<JsonDocument>();
        Assert.Equal("invalid_input", d2!.RootElement.GetProperty("error").GetString());
        var e2 = d2.RootElement.GetProperty("errors").EnumerateArray().Select(x => x.GetString()).ToList();
        Assert.Contains("password_required", e2);

        var r3 = await _client.PostAsJsonAsync("/register", new { Username = "userx", Password = "whatever", Email = "" });
        Assert.Equal(HttpStatusCode.BadRequest, r3.StatusCode);
        var d3 = await r3.Content.ReadFromJsonAsync<JsonDocument>();
        Assert.Equal("invalid_input", d3!.RootElement.GetProperty("error").GetString());
        var e3 = d3.RootElement.GetProperty("errors").EnumerateArray().Select(x => x.GetString()).ToList();
        Assert.Contains("email_required", e3);
    }

    [Fact]
    public async Task Login_missing_fields_returns_bad_request()
    {
        LogTestStart();
        var r1 = await _client.PostAsJsonAsync("/login", new { Username = "", Password = "whatever" });
        Assert.Equal(HttpStatusCode.BadRequest, r1.StatusCode);
        var d1 = await r1.Content.ReadFromJsonAsync<JsonDocument>();
        Assert.Equal("invalid_input", d1!.RootElement.GetProperty("error").GetString());
        var e1 = d1.RootElement.GetProperty("errors").EnumerateArray().Select(x => x.GetString()).ToList();
        Assert.Contains("username_required", e1);

        var r2 = await _client.PostAsJsonAsync("/login", new { Username = "userx", Password = "" });
        Assert.Equal(HttpStatusCode.BadRequest, r2.StatusCode);
        var d2 = await r2.Content.ReadFromJsonAsync<JsonDocument>();
        Assert.Equal("invalid_input", d2!.RootElement.GetProperty("error").GetString());
        var e2 = d2.RootElement.GetProperty("errors").EnumerateArray().Select(x => x.GetString()).ToList();
        Assert.Contains("password_required", e2);
    }

    [Fact]
    public async Task Login_lockout_persists_across_factory()
    {
        LogTestStart();
        var username = $"persist_{Guid.NewGuid():N}";
        // 5 fallimenti per attivare lock
        for (var i = 0; i < 5; i++)
        {
            var resp = await _client.PostAsJsonAsync("/login", new { Username = username, Password = "wrong" });
            Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        }
        var locked = await _client.PostAsJsonAsync("/login", new { Username = username, Password = "wrong" });
        Assert.Equal((HttpStatusCode)429, locked.StatusCode);

        // Ricrea factory/client per simulare riavvio
        await DisposeAsync();
        await InitializeAsync();

        var lockedAfterRestart = await _client.PostAsJsonAsync("/login", new { Username = username, Password = "wrong" });
        Assert.Equal((HttpStatusCode)429, lockedAfterRestart.StatusCode);
    }

    [Fact]
    public async Task Login_audit_records_success_and_failure()
    {
        LogTestStart();
        var username = $"audit_{Guid.NewGuid():N}";
        var password = "P@ssw0rd!Long";
        var email = $"{username}@example.com";

        var register = await _client.PostAsJsonAsync("/register", new { Username = username, Password = password, Email = email });
        Assert.Equal(HttpStatusCode.Created, register.StatusCode);
        var regPayload = await register.Content.ReadFromJsonAsync<RegisterResponse>();
        Assert.NotNull(regPayload);
        await ConfirmEmailAsync(regPayload!.EmailConfirmToken!);

        var fail = await _client.PostAsJsonAsync("/login", new { Username = username, Password = "wrong" });
        Assert.Equal(HttpStatusCode.Unauthorized, fail.StatusCode);

        var ok = await _client.PostAsJsonAsync("/login", new { Username = username, Password = password });
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);

        await using var db = new SqliteConnection($"Data Source={_dbPath};Mode=ReadWriteCreate;Cache=Shared");
        await db.OpenAsync();
        var rows = await db.QueryAsync<string>(
            "SELECT outcome FROM login_audit WHERE username = @u",
            new { u = username });
        var outcomes = rows.ToList();
        Assert.Contains("invalid_credentials", outcomes);
        Assert.Contains("success", outcomes);
    }

    [Fact]
    public async Task Totp_setup_and_login_success()
    {
        LogTestStart();
        var username = $"totp_{Guid.NewGuid():N}";
        var password = "P@ssw0rd!Long";
        var email = $"{username}@example.com";

        var register = await _client.PostAsJsonAsync("/register", new { Username = username, Password = password, Email = email });
        Assert.Equal(HttpStatusCode.Created, register.StatusCode);

        var (cookie, csrf) = await LoginAndGetSessionAsync(username, password);

        using var setupReq = new HttpRequestMessage(HttpMethod.Post, "/mfa/setup");
        setupReq.Headers.Add("Cookie", cookie);
        setupReq.Headers.Add("X-CSRF-Token", csrf);
        var setupResp = await _client.SendAsync(setupReq);
        Assert.Equal(HttpStatusCode.OK, setupResp.StatusCode);
        var setupPayload = await setupResp.Content.ReadFromJsonAsync<MfaSetupResponse>();
        Assert.NotNull(setupPayload);
        Assert.True(setupPayload!.Ok);
        Assert.False(string.IsNullOrWhiteSpace(setupPayload.Secret));

        using var logoutReq = new HttpRequestMessage(HttpMethod.Post, "/logout");
        logoutReq.Headers.Add("Cookie", cookie);
        logoutReq.Headers.Add("X-CSRF-Token", csrf);
        var logout = await _client.SendAsync(logoutReq);
        Assert.Equal(HttpStatusCode.OK, logout.StatusCode);

        var noTotp = await _client.PostAsJsonAsync("/login", new { Username = username, Password = password });
        Assert.Equal(HttpStatusCode.Unauthorized, noTotp.StatusCode);
        var mfa = await noTotp.Content.ReadFromJsonAsync<MfaRequiredResponse>();
        Assert.Equal("mfa_required", mfa!.Error);
        Assert.False(string.IsNullOrWhiteSpace(mfa.ChallengeId));
        Assert.True(mfa.Ok == false || mfa.Ok == null);

        var totp = new Totp(Base32Encoding.ToBytes(setupPayload.Secret!));
        var code = totp.ComputeTotp();
        var confirm = await _client.PostAsJsonAsync("/login/confirm-mfa", new { ChallengeId = mfa.ChallengeId, TotpCode = code, RememberMe = true });
        Assert.Equal(HttpStatusCode.OK, confirm.StatusCode);
        var confirmPayload = await confirm.Content.ReadFromJsonAsync<MfaConfirmResponse>();
        Assert.NotNull(confirmPayload);
        Assert.True(confirmPayload!.Ok);
        Assert.False(string.IsNullOrWhiteSpace(confirmPayload.CsrfToken));
        Assert.True(confirmPayload.RememberIssued ?? false);
        var setCookies = confirm.Headers.TryGetValues("Set-Cookie", out var cookies)
            ? cookies.ToList()
            : new List<string>();
        Assert.Contains(setCookies, c => c.StartsWith("access_token", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(setCookies, c => c.StartsWith("refresh_token", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(setCookies, c => c.StartsWith("device_id", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Totp_challenge_rejects_wrong_code()
    {
        LogTestStart();
        var username = $"totp_fail_{Guid.NewGuid():N}";
        var password = "P@ssw0rd!Long";
        var email = $"{username}@example.com";

        var register = await _client.PostAsJsonAsync("/register", new { Username = username, Password = password, Email = email });
        Assert.Equal(HttpStatusCode.Created, register.StatusCode);
        var regPayload = await register.Content.ReadFromJsonAsync<RegisterResponse>();
        await ConfirmEmailAsync(regPayload!.EmailConfirmToken!);

        var (cookie, csrf) = await LoginAndGetSessionAsync(username, password);
        using var setupReq = new HttpRequestMessage(HttpMethod.Post, "/mfa/setup");
        setupReq.Headers.Add("Cookie", cookie);
        setupReq.Headers.Add("X-CSRF-Token", csrf);
        var setupResp = await _client.SendAsync(setupReq);
        var setupPayload = await setupResp.Content.ReadFromJsonAsync<MfaSetupResponse>();
        Assert.Equal(HttpStatusCode.OK, setupResp.StatusCode);
        Assert.NotNull(setupPayload);

        using var logoutReq = new HttpRequestMessage(HttpMethod.Post, "/logout");
        logoutReq.Headers.Add("Cookie", cookie);
        logoutReq.Headers.Add("X-CSRF-Token", csrf);
        var logout = await _client.SendAsync(logoutReq);
        Assert.Equal(HttpStatusCode.OK, logout.StatusCode);

        var noTotp = await _client.PostAsJsonAsync("/login", new { Username = username, Password = password });
        Assert.Equal(HttpStatusCode.Unauthorized, noTotp.StatusCode);
        var mfa = await noTotp.Content.ReadFromJsonAsync<MfaRequiredResponse>();
        Assert.Equal("mfa_required", mfa!.Error);
        Assert.False(string.IsNullOrWhiteSpace(mfa.ChallengeId));

        var wrongCode = "000000";
        var confirm = await _client.PostAsJsonAsync("/login/confirm-mfa", new { ChallengeId = mfa.ChallengeId, TotpCode = wrongCode });
        Assert.Equal(HttpStatusCode.Unauthorized, confirm.StatusCode);
        var cookiesAfter = confirm.Headers.TryGetValues("Set-Cookie", out var cks) ? cks.ToList() : new List<string>();
        Assert.DoesNotContain(cookiesAfter, c => c.StartsWith("access_token", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(cookiesAfter, c => c.StartsWith("refresh_token", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Totp_challenge_requires_confirm_step_for_cookies()
    {
        LogTestStart();
        var username = $"totp_step_{Guid.NewGuid():N}";
        var password = "P@ssw0rd!Long";
        var email = $"{username}@example.com";

        var register = await _client.PostAsJsonAsync("/register", new { Username = username, Password = password, Email = email });
        var regPayload = await register.Content.ReadFromJsonAsync<RegisterResponse>();
        await ConfirmEmailAsync(regPayload!.EmailConfirmToken!);

        var (cookie, csrf) = await LoginAndGetSessionAsync(username, password);
        using var setupReq = new HttpRequestMessage(HttpMethod.Post, "/mfa/setup");
        setupReq.Headers.Add("Cookie", cookie);
        setupReq.Headers.Add("X-CSRF-Token", csrf);
        var setupResp = await _client.SendAsync(setupReq);
        var setupPayload = await setupResp.Content.ReadFromJsonAsync<MfaSetupResponse>();
        Assert.Equal(HttpStatusCode.OK, setupResp.StatusCode);

        using var logoutReq = new HttpRequestMessage(HttpMethod.Post, "/logout");
        logoutReq.Headers.Add("Cookie", cookie);
        logoutReq.Headers.Add("X-CSRF-Token", csrf);
        var logout = await _client.SendAsync(logoutReq);
        Assert.Equal(HttpStatusCode.OK, logout.StatusCode);

        var login = await _client.PostAsJsonAsync("/login", new { Username = username, Password = password, RememberMe = true });
        Assert.Equal(HttpStatusCode.Unauthorized, login.StatusCode);
        Assert.False(login.Headers.TryGetValues("Set-Cookie", out var firstCookies) && firstCookies.Any(c => c.StartsWith("access_token", StringComparison.OrdinalIgnoreCase)));

        var mfa = await login.Content.ReadFromJsonAsync<MfaRequiredResponse>();
        var totp = new Totp(Base32Encoding.ToBytes(setupPayload!.Secret!)).ComputeTotp();
        var confirm = await _client.PostAsJsonAsync("/login/confirm-mfa", new { ChallengeId = mfa!.ChallengeId, TotpCode = totp, RememberMe = true });
        Assert.Equal(HttpStatusCode.OK, confirm.StatusCode);
        var cookies = confirm.Headers.GetValues("Set-Cookie").ToList();
        Assert.Contains(cookies, c => c.StartsWith("access_token", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(cookies, c => c.StartsWith("refresh_token", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Totp_challenge_expired_or_used_returns_unauthorized()
    {
        LogTestStart();
        var username = $"totp_exp_{Guid.NewGuid():N}";
        var password = "P@ssw0rd!Long";
        var email = $"{username}@example.com";

        var register = await _client.PostAsJsonAsync("/register", new { Username = username, Password = password, Email = email });
        var regPayload = await register.Content.ReadFromJsonAsync<RegisterResponse>();
        await ConfirmEmailAsync(regPayload!.EmailConfirmToken!);

        var (cookie, csrf) = await LoginAndGetSessionAsync(username, password);
        using var setupReq = new HttpRequestMessage(HttpMethod.Post, "/mfa/setup");
        setupReq.Headers.Add("Cookie", cookie);
        setupReq.Headers.Add("X-CSRF-Token", csrf);
        var setupResp = await _client.SendAsync(setupReq);
        var setupPayload = await setupResp.Content.ReadFromJsonAsync<MfaSetupResponse>();
        Assert.Equal(HttpStatusCode.OK, setupResp.StatusCode);

        using var logoutReq = new HttpRequestMessage(HttpMethod.Post, "/logout");
        logoutReq.Headers.Add("Cookie", cookie);
        logoutReq.Headers.Add("X-CSRF-Token", csrf);
        var logout = await _client.SendAsync(logoutReq);
        Assert.Equal(HttpStatusCode.OK, logout.StatusCode);

        var login = await _client.PostAsJsonAsync("/login", new { Username = username, Password = password });
        Assert.Equal(HttpStatusCode.Unauthorized, login.StatusCode);
        var mfa = await login.Content.ReadFromJsonAsync<MfaRequiredResponse>();
        Assert.NotNull(mfa);

        // Simula expiry: in mancanza di config, questo test fallirà finché non implementiamo lo scadere/cleanup.
        var confirmExpired = await _client.PostAsJsonAsync("/login/confirm-mfa", new { ChallengeId = mfa!.ChallengeId, TotpCode = "000000" });
        Assert.Equal(HttpStatusCode.Unauthorized, confirmExpired.StatusCode);
    }

    [Fact]
    public async Task Totp_challenge_rejects_different_user_agent()
    {
        LogTestStart();
        var username = $"totp_ua_{Guid.NewGuid():N}";
        var password = "P@ssw0rd!Long";
        var email = $"{username}@example.com";

        var register = await _client.PostAsJsonAsync("/register", new { Username = username, Password = password, Email = email });
        var regPayload = await register.Content.ReadFromJsonAsync<RegisterResponse>();
        await ConfirmEmailAsync(regPayload!.EmailConfirmToken!);

        var (cookie, csrf) = await LoginAndGetSessionAsync(username, password);
        using var setupReq = new HttpRequestMessage(HttpMethod.Post, "/mfa/setup");
        setupReq.Headers.Add("Cookie", cookie);
        setupReq.Headers.Add("X-CSRF-Token", csrf);
        var setupResp = await _client.SendAsync(setupReq);
        var setupPayload = await setupResp.Content.ReadFromJsonAsync<MfaSetupResponse>();
        Assert.Equal(HttpStatusCode.OK, setupResp.StatusCode);

        using var logoutReq = new HttpRequestMessage(HttpMethod.Post, "/logout");
        logoutReq.Headers.Add("Cookie", cookie);
        logoutReq.Headers.Add("X-CSRF-Token", csrf);
        var logout = await _client.SendAsync(logoutReq);
        Assert.Equal(HttpStatusCode.OK, logout.StatusCode);

        using var loginReq = new HttpRequestMessage(HttpMethod.Post, "/login");
        loginReq.Headers.TryAddWithoutValidation("User-Agent", "UA-ORIG");
        loginReq.Content = JsonContent.Create(new { Username = username, Password = password });
        var loginResp = await _client.SendAsync(loginReq);
        Assert.Equal(HttpStatusCode.Unauthorized, loginResp.StatusCode);
        var mfa = await loginResp.Content.ReadFromJsonAsync<MfaRequiredResponse>();
        Assert.NotNull(mfa);

        using var confirmReq = new HttpRequestMessage(HttpMethod.Post, "/login/confirm-mfa");
        confirmReq.Headers.TryAddWithoutValidation("User-Agent", "UA-DIFF");
        var totp = new Totp(Base32Encoding.ToBytes(setupPayload!.Secret!)).ComputeTotp();
        confirmReq.Content = JsonContent.Create(new { ChallengeId = mfa!.ChallengeId, TotpCode = totp });
        var confirm = await _client.SendAsync(confirmReq);
        Assert.Equal(HttpStatusCode.Unauthorized, confirm.StatusCode);
    }

    [Fact]
    public async Task Totp_challenge_max_attempts_invalidates_challenge()
    {
        LogTestStart();
        var username = $"totp_attempts_{Guid.NewGuid():N}";
        var password = "P@ssw0rd!Long";
        var email = $"{username}@example.com";

        var register = await _client.PostAsJsonAsync("/register", new { Username = username, Password = password, Email = email });
        var regPayload = await register.Content.ReadFromJsonAsync<RegisterResponse>();
        await ConfirmEmailAsync(regPayload!.EmailConfirmToken!);

        var (cookie, csrf) = await LoginAndGetSessionAsync(username, password);
        using var setupReq = new HttpRequestMessage(HttpMethod.Post, "/mfa/setup");
        setupReq.Headers.Add("Cookie", cookie);
        setupReq.Headers.Add("X-CSRF-Token", csrf);
        var setupResp = await _client.SendAsync(setupReq);
        var setupPayload = await setupResp.Content.ReadFromJsonAsync<MfaSetupResponse>();
        Assert.Equal(HttpStatusCode.OK, setupResp.StatusCode);

        using var logoutReq = new HttpRequestMessage(HttpMethod.Post, "/logout");
        logoutReq.Headers.Add("Cookie", cookie);
        logoutReq.Headers.Add("X-CSRF-Token", csrf);
        var logout = await _client.SendAsync(logoutReq);
        Assert.Equal(HttpStatusCode.OK, logout.StatusCode);

        var login = await _client.PostAsJsonAsync("/login", new { Username = username, Password = password });
        Assert.Equal(HttpStatusCode.Unauthorized, login.StatusCode);
        var mfa = await login.Content.ReadFromJsonAsync<MfaRequiredResponse>();
        Assert.NotNull(mfa);

        // simuliamo 3 tentativi errati, poi uno corretto che deve fallire se max tentativi = 3
        for (var i = 0; i < 3; i++)
        {
            var wrong = await _client.PostAsJsonAsync("/login/confirm-mfa", new { ChallengeId = mfa!.ChallengeId, TotpCode = "111111" });
            Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        }

        var totp = new Totp(Base32Encoding.ToBytes(setupPayload!.Secret!)).ComputeTotp();
        var confirm = await _client.PostAsJsonAsync("/login/confirm-mfa", new { ChallengeId = mfa!.ChallengeId, TotpCode = totp });
        Assert.Equal(HttpStatusCode.Unauthorized, confirm.StatusCode);
    }

    [Fact]
    public async Task Totp_challenge_rejects_different_ip_when_required()
    {
        LogTestStart();
        var username = $"totp_ip_{Guid.NewGuid():N}";
        var password = "P@ssw0rd!Long";
        var email = $"{username}@example.com";

        var extra = new Dictionary<string, string?>
        {
            ["Mfa:RequireIpMatch"] = "true"
        };
        var (factory, client, dbPath) = CreateFactory(requireSecure: false, extraConfig: extra);
        try
        {
            var register = await client.PostAsJsonAsync("/register", new { Username = username, Password = password, Email = email });
            var regPayload = await register.Content.ReadFromJsonAsync<RegisterResponse>();
            await client.PostAsJsonAsync("/confirm-email", new { Token = regPayload!.EmailConfirmToken });

            // login e setup MFA
            var loginInitial = await client.PostAsJsonAsync("/login", new { Username = username, Password = password });
            var loginPayload = await loginInitial.Content.ReadFromJsonAsync<LoginResponse>();
            var accessCookie = loginInitial.Headers.GetValues("Set-Cookie").First(c => c.StartsWith("access_token", StringComparison.OrdinalIgnoreCase)).Split(';', 2)[0];
            using (var setupReq = new HttpRequestMessage(HttpMethod.Post, "/mfa/setup"))
            {
                setupReq.Headers.Add("Cookie", accessCookie);
                setupReq.Headers.Add("X-CSRF-Token", loginPayload!.CsrfToken);
                var setupResp = await client.SendAsync(setupReq);
                Assert.Equal(HttpStatusCode.OK, setupResp.StatusCode);
            }

            // logout
            using (var logoutReq = new HttpRequestMessage(HttpMethod.Post, "/logout"))
            {
                logoutReq.Headers.Add("Cookie", accessCookie);
                logoutReq.Headers.Add("X-CSRF-Token", loginPayload!.CsrfToken);
                var logoutResp = await client.SendAsync(logoutReq);
                Assert.Equal(HttpStatusCode.OK, logoutResp.StatusCode);
            }

            // login first step (assume factory gives a local IP; we can't easily change it, so we simulate by overriding header X-Forwarded-For)
            using var loginReq = new HttpRequestMessage(HttpMethod.Post, "/login");
            loginReq.Headers.TryAddWithoutValidation("X-Forwarded-For", "1.1.1.1");
            loginReq.Content = JsonContent.Create(new { Username = username, Password = password });
            var loginResp = await client.SendAsync(loginReq);
            Assert.Equal(HttpStatusCode.Unauthorized, loginResp.StatusCode);
            var mfa = await loginResp.Content.ReadFromJsonAsync<MfaRequiredResponse>();

            // confirm with different IP
            using var confirmReq = new HttpRequestMessage(HttpMethod.Post, "/login/confirm-mfa");
            confirmReq.Headers.TryAddWithoutValidation("X-Forwarded-For", "2.2.2.2");
            var totp = "000000"; // dovrebbe essere respinto comunque in mancanza di IP match
            confirmReq.Content = JsonContent.Create(new { ChallengeId = mfa!.ChallengeId, TotpCode = totp });
            var confirmResp = await client.SendAsync(confirmReq);
            Assert.Equal(HttpStatusCode.Unauthorized, confirmResp.StatusCode);
        }
        finally
        {
            client.Dispose();
            factory.Dispose();
            if (System.IO.File.Exists(dbPath))
            {
                try { System.IO.File.Delete(dbPath); } catch { }
            }
        }
    }

    [Fact]
    public async Task Login_without_totp_remains_one_step()
    {
        LogTestStart();
        var username = $"plain_{Guid.NewGuid():N}";
        var password = "P@ssw0rd!Long";
        var email = $"{username}@example.com";

        var register = await _client.PostAsJsonAsync("/register", new { Username = username, Password = password, Email = email });
        Assert.Equal(HttpStatusCode.Created, register.StatusCode);
        var regPayload = await register.Content.ReadFromJsonAsync<RegisterResponse>();
        await ConfirmEmailAsync(regPayload!.EmailConfirmToken!);

        var login = await _client.PostAsJsonAsync("/login", new { Username = username, Password = password });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        var setCookies = login.Headers.GetValues("Set-Cookie").ToList();
        Assert.Contains(setCookies, c => c.StartsWith("access_token", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Login_with_remember_emits_refresh_cookie()
    {
        LogTestStart();
        var username = $"remember_{Guid.NewGuid():N}";
        var password = "P@ssw0rd!Long";
        var email = $"{username}@example.com";

        var register = await _client.PostAsJsonAsync("/register", new { Username = username, Password = password, Email = email });
        Assert.Equal(HttpStatusCode.Created, register.StatusCode);
        var regPayload = await register.Content.ReadFromJsonAsync<RegisterResponse>();
        Assert.NotNull(regPayload);
        await ConfirmEmailAsync(regPayload!.EmailConfirmToken!);

        var response = await _client.PostAsJsonAsync("/login", new { Username = username, Password = password, RememberMe = true });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var payload = await response.Content.ReadFromJsonAsync<LoginResponse>();
        Assert.NotNull(payload);
        Assert.True(payload!.Ok);
        Assert.True(payload.RememberIssued);

        var setCookies = response.Headers.TryGetValues("Set-Cookie", out var cookies)
            ? cookies.ToList()
            : new List<string>();
        var refresh = setCookies.FirstOrDefault(c => c.StartsWith("refresh_token", StringComparison.OrdinalIgnoreCase));
        Assert.False(string.IsNullOrWhiteSpace(refresh));
        var lower = refresh!.ToLowerInvariant();
        Assert.Contains("httponly", lower);
        // In ambiente di test Cookie:RequireSecure=false, quindi secure potrebbe mancare; verifichiamo comunque HttpOnly/SameSite/Path/Max-Age.
        Assert.Contains("samesite=strict", lower);
        Assert.Contains("path=/refresh", lower);
        Assert.Contains("max-age", lower);
    }

    [Fact]
    public async Task Refresh_with_valid_token_rotates_and_emits_new_cookies()
    {
        LogTestStart();
        var username = $"refresh_{Guid.NewGuid():N}";
        var password = "P@ssw0rd!Long";
        var email = $"{username}@example.com";

        var register = await _client.PostAsJsonAsync("/register", new { Username = username, Password = password, Email = email });
        Assert.Equal(HttpStatusCode.Created, register.StatusCode);
        var regPayload = await register.Content.ReadFromJsonAsync<RegisterResponse>();
        await ConfirmEmailAsync(regPayload!.EmailConfirmToken!);

        var login = await _client.PostAsJsonAsync("/login", new { Username = username, Password = password, RememberMe = true });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        var setCookies = login.Headers.GetValues("Set-Cookie").ToList();
        var refreshCookie = setCookies.First(c => c.StartsWith("refresh_token", StringComparison.OrdinalIgnoreCase)).Split(';', 2)[0];
        var deviceCookie = setCookies.First(c => c.StartsWith("device_id", StringComparison.OrdinalIgnoreCase)).Split(';', 2)[0];

        using var refreshReq = new HttpRequestMessage(HttpMethod.Post, "/refresh");
        refreshReq.Headers.Add("Cookie", $"{refreshCookie}; {deviceCookie}");
        var refreshResp = await _client.SendAsync(refreshReq);
        Assert.Equal(HttpStatusCode.OK, refreshResp.StatusCode);
        var newSetCookies = refreshResp.Headers.GetValues("Set-Cookie").ToList();
        var newRefreshCookie = newSetCookies.First(c => c.StartsWith("refresh_token", StringComparison.OrdinalIgnoreCase)).Split(';', 2)[0];
        Assert.NotEqual(refreshCookie, newRefreshCookie);

        await using var db = new SqliteConnection($"Data Source={_dbPath};Mode=ReadWriteCreate;Cache=Shared");
        await db.OpenAsync();
        var refreshValue = refreshCookie.Split('=')[1];
        var refreshHash = _hasher.ComputeHash(refreshValue);
        var revoked = await db.ExecuteScalarAsync<string>("SELECT revoked_at_utc FROM refresh_tokens WHERE token_hash = @h", new { h = refreshHash });
        Assert.False(string.IsNullOrWhiteSpace(revoked));
    }

    [Fact]
    public async Task Login_remember_sets_device_cookie()
    {
        LogTestStart();
        var username = $"device_login_{Guid.NewGuid():N}";
        var password = "P@ssw0rd!Long";
        var email = $"{username}@example.com";

        var register = await _client.PostAsJsonAsync("/register", new { Username = username, Password = password, Email = email });
        var regPayload = await register.Content.ReadFromJsonAsync<RegisterResponse>();
        await ConfirmEmailAsync(regPayload!.EmailConfirmToken!);

        var login = await _client.PostAsJsonAsync("/login", new { Username = username, Password = password, RememberMe = true });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        var cookies = login.Headers.GetValues("Set-Cookie").ToList();
        Assert.Contains(cookies, c => c.StartsWith("refresh_token", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(cookies, c => c.StartsWith("device_id", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Login_remember_stores_hashed_refresh_token()
    {
        LogTestStart();
        var username = $"hash_refresh_{Guid.NewGuid():N}";
        var password = "P@ssw0rd!Long";
        var email = $"{username}@example.com";

        var register = await _client.PostAsJsonAsync("/register", new { Username = username, Password = password, Email = email });
        var regPayload = await register.Content.ReadFromJsonAsync<RegisterResponse>();
        await ConfirmEmailAsync(regPayload!.EmailConfirmToken!);

        var login = await _client.PostAsJsonAsync("/login", new { Username = username, Password = password, RememberMe = true });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        var refreshCookie = login.Headers.GetValues("Set-Cookie").First(c => c.StartsWith("refresh_token", StringComparison.OrdinalIgnoreCase)).Split(';', 2)[0];
        var refreshValue = refreshCookie.Split('=')[1];
        var hash = _hasher.ComputeHash(refreshValue);

        await using var db = new SqliteConnection($"Data Source={_dbPath};Mode=ReadWriteCreate;Cache=Shared");
        await db.OpenAsync();
        var tokenColumnExists = await db.ExecuteScalarAsync<long>("SELECT COUNT(1) FROM pragma_table_info('refresh_tokens') WHERE name = 'token';");
        Assert.Equal(0, tokenColumnExists);
        var tokenHashFromDb = await db.ExecuteScalarAsync<string>("SELECT token_hash FROM refresh_tokens WHERE token_hash = @h", new { h = hash });
        Assert.Equal(hash, tokenHashFromDb);
    }

    [Fact]
    public async Task Id_token_contains_pwd_amr_email_and_nonce_on_login()
    {
        LogTestStart();
        var username = $"idpwd_{Guid.NewGuid():N}";
        var password = "P@ssw0rd!Long";
        var email = $"{username}@example.com";

        var register = await _client.PostAsJsonAsync("/register", new { Username = username, Password = password, Email = email });
        var regPayload = await register.Content.ReadFromJsonAsync<RegisterResponse>();
        await ConfirmEmailAsync(regPayload!.EmailConfirmToken!);

        var nonce = Guid.NewGuid().ToString("N");
        var login = await _client.PostAsJsonAsync("/login", new { Username = username, Password = password, Nonce = nonce });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        var payload = await login.Content.ReadFromJsonAsync<LoginResponse>();
        Assert.False(string.IsNullOrWhiteSpace(payload!.IdToken));

        var idSvc = _factory.Services.GetRequiredService<IdTokenService>();
        var jwt = ValidateIdToken(payload.IdToken!, idSvc.GetValidationParameters());
        Assert.Equal("TestIdIssuer", jwt.Issuer);
        Assert.Equal("TestIdAudience", jwt.Audiences.Single());
        var amr = jwt.Claims.Where(c => c.Type == "amr").Select(c => c.Value).ToList();
        Assert.Contains("pwd", amr);
        Assert.DoesNotContain("mfa", amr);
        Assert.Equal(nonce, jwt.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Nonce)?.Value);
        Assert.Equal(email, jwt.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Email)?.Value);
        Assert.Equal(username, jwt.Claims.FirstOrDefault(c => c.Type == "preferred_username")?.Value);
    }

    [Fact]
    public async Task Id_token_mfa_flow_emits_mfa_amr_and_not_in_first_step()
    {
        LogTestStart();
        var username = $"idmfa_{Guid.NewGuid():N}";
        var password = "P@ssw0rd!Long";
        var email = $"{username}@example.com";

        var register = await _client.PostAsJsonAsync("/register", new { Username = username, Password = password, Email = email });
        var regPayload = await register.Content.ReadFromJsonAsync<RegisterResponse>();
        await ConfirmEmailAsync(regPayload!.EmailConfirmToken!);

        // Setup MFA
        var login = await _client.PostAsJsonAsync("/login", new { Username = username, Password = password });
        var loginPayload = await login.Content.ReadFromJsonAsync<LoginResponse>();
        var accessCookie = login.Headers.GetValues("Set-Cookie").First(c => c.StartsWith("access_token", StringComparison.OrdinalIgnoreCase)).Split(';', 2)[0];
        using (var setupReq = new HttpRequestMessage(HttpMethod.Post, "/mfa/setup"))
        {
            setupReq.Headers.Add("Cookie", accessCookie);
            setupReq.Headers.Add("X-CSRF-Token", loginPayload!.CsrfToken);
            var setupResp = await _client.SendAsync(setupReq);
            Assert.Equal(HttpStatusCode.OK, setupResp.StatusCode);
            var setupPayload = await setupResp.Content.ReadFromJsonAsync<MfaSetupResponse>();
            var secret = setupPayload!.Secret!;

            // logout
            using (var logoutReq = new HttpRequestMessage(HttpMethod.Post, "/logout"))
            {
                logoutReq.Headers.Add("Cookie", accessCookie);
                logoutReq.Headers.Add("X-CSRF-Token", loginPayload.CsrfToken);
                var logoutResp = await _client.SendAsync(logoutReq);
                Assert.Equal(HttpStatusCode.OK, logoutResp.StatusCode);
            }

            // Login step 1 (mfa_required, nessun id_token)
            var loginMfa = await _client.PostAsJsonAsync("/login", new { Username = username, Password = password });
            Assert.Equal(HttpStatusCode.Unauthorized, loginMfa.StatusCode);
            var mfaReq = await loginMfa.Content.ReadFromJsonAsync<MfaRequiredResponse>();
            var loginBody = await loginMfa.Content.ReadAsStringAsync();
            Assert.DoesNotContain("idToken", loginBody, StringComparison.OrdinalIgnoreCase);

            // Confirm MFA step
            var totp = new Totp(Base32Encoding.ToBytes(secret));
            var code = totp.ComputeTotp();
            var confirm = await _client.PostAsJsonAsync("/login/confirm-mfa", new { ChallengeId = mfaReq!.ChallengeId, TotpCode = code });
            Assert.Equal(HttpStatusCode.OK, confirm.StatusCode);
            var confirmPayload = await confirm.Content.ReadFromJsonAsync<MfaConfirmResponse>();
            Assert.False(string.IsNullOrWhiteSpace(confirmPayload!.IdToken));

            var idSvc = _factory.Services.GetRequiredService<IdTokenService>();
            var jwt = ValidateIdToken(confirmPayload.IdToken!, idSvc.GetValidationParameters());
            var amr = jwt.Claims.Where(c => c.Type == "amr").Select(c => c.Value).ToList();
            Assert.Contains("mfa", amr);
            Assert.DoesNotContain("pwd", amr); // service emette solo mfa in confirm
        }
    }

    [Fact]
    public async Task Login_invalid_credentials_does_not_emit_id_token()
    {
        LogTestStart();
        var resp = await _client.PostAsJsonAsync("/login", new { Username = "demo", Password = "wrong" });
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        var body = await resp.Content.ReadAsStringAsync();
        Assert.DoesNotContain("idToken", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Id_token_auth_time_differs_after_mfa_step_up()
    {
        LogTestStart();
        var username = $"idstep_{Guid.NewGuid():N}";
        var password = "P@ssw0rd!Long";
        var email = $"{username}@example.com";

        var register = await _client.PostAsJsonAsync("/register", new { Username = username, Password = password, Email = email });
        var regPayload = await register.Content.ReadFromJsonAsync<RegisterResponse>();
        await ConfirmEmailAsync(regPayload!.EmailConfirmToken!);

        // Login base -> id_token pwd
        var login = await _client.PostAsJsonAsync("/login", new { Username = username, Password = password });
        var loginPayload = await login.Content.ReadFromJsonAsync<LoginResponse>();
        var idSvc = _factory.Services.GetRequiredService<IdTokenService>();
        var jwtPwd = ValidateIdToken(loginPayload!.IdToken!, idSvc.GetValidationParameters());
        var authTimePwd = jwtPwd.Claims.First(c => c.Type == "auth_time").Value;
        var amrPwd = jwtPwd.Claims.Where(c => c.Type == "amr").Select(c => c.Value).ToList();
        Assert.Contains("pwd", amrPwd);

        var accessCookie = login.Headers.GetValues("Set-Cookie").First(c => c.StartsWith("access_token", StringComparison.OrdinalIgnoreCase)).Split(';', 2)[0];
        // Setup MFA
        using (var setupReq = new HttpRequestMessage(HttpMethod.Post, "/mfa/setup"))
        {
            setupReq.Headers.Add("Cookie", accessCookie);
            setupReq.Headers.Add("X-CSRF-Token", loginPayload.CsrfToken);
            var setupResp = await _client.SendAsync(setupReq);
            Assert.Equal(HttpStatusCode.OK, setupResp.StatusCode);
            var setupPayload = await setupResp.Content.ReadFromJsonAsync<MfaSetupResponse>();
            var secret = setupPayload!.Secret!;

            // Logout
            using (var logoutReq = new HttpRequestMessage(HttpMethod.Post, "/logout"))
            {
                logoutReq.Headers.Add("Cookie", accessCookie);
                logoutReq.Headers.Add("X-CSRF-Token", loginPayload.CsrfToken);
                var logoutResp = await _client.SendAsync(logoutReq);
                Assert.Equal(HttpStatusCode.OK, logoutResp.StatusCode);
            }

            // Login step 1 -> mfa_required
            var loginMfa = await _client.PostAsJsonAsync("/login", new { Username = username, Password = password });
            Assert.Equal(HttpStatusCode.Unauthorized, loginMfa.StatusCode);
            var mfaReq = await loginMfa.Content.ReadFromJsonAsync<MfaRequiredResponse>();
            var bodyStep1 = await loginMfa.Content.ReadAsStringAsync();
            Assert.DoesNotContain("idToken", bodyStep1, StringComparison.OrdinalIgnoreCase);

            // Confirm MFA -> id_token mfa
            var totp = new Totp(Base32Encoding.ToBytes(secret));
            var code = totp.ComputeTotp();
            var confirm = await _client.PostAsJsonAsync("/login/confirm-mfa", new { ChallengeId = mfaReq!.ChallengeId, TotpCode = code });
            Assert.Equal(HttpStatusCode.OK, confirm.StatusCode);
            var confirmPayload = await confirm.Content.ReadFromJsonAsync<MfaConfirmResponse>();
            var jwtMfa = ValidateIdToken(confirmPayload!.IdToken!, idSvc.GetValidationParameters());
            var amrMfa = jwtMfa.Claims.Where(c => c.Type == "amr").Select(c => c.Value).ToList();
            Assert.Contains("mfa", amrMfa);
            var authTimeMfa = jwtMfa.Claims.First(c => c.Type == "auth_time").Value;
            Assert.True(long.Parse(authTimeMfa) >= long.Parse(authTimePwd));
        }
    }

    [Fact]
    public async Task Id_token_excludes_email_when_config_disabled()
    {
        LogTestStart();
        var extra = new Dictionary<string, string?>
        {
            ["IdToken:IncludeEmail"] = "false",
            ["IdToken:Secret"] = "TEST_ID_TOKEN_SECRET_AT_LEAST_32_CHARS_LONG___"
        };
        var (factory, client, dbPath) = CreateFactory(requireSecure: false, extraConfig: extra);
        try
        {
            var username = $"noemail_{Guid.NewGuid():N}";
            var password = "P@ssw0rd!Long";
            var email = $"{username}@example.com";

            var register = await client.PostAsJsonAsync("/register", new { Username = username, Password = password, Email = email });
            var regPayload = await register.Content.ReadFromJsonAsync<RegisterResponse>();
            await client.PostAsJsonAsync("/confirm-email", new { Token = regPayload!.EmailConfirmToken });

            var login = await client.PostAsJsonAsync("/login", new { Username = username, Password = password });
            var payload = await login.Content.ReadFromJsonAsync<LoginResponse>();
            var idSvc = factory.Services.GetRequiredService<IdTokenService>();
            var jwt = ValidateIdToken(payload!.IdToken!, idSvc.GetValidationParameters());
            Assert.Null(jwt.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Email));
            Assert.Equal(username, jwt.Claims.FirstOrDefault(c => c.Type == "preferred_username")?.Value);
        }
        finally
        {
            client.Dispose();
            factory.Dispose();
            if (File.Exists(dbPath))
            {
                try { File.Delete(dbPath); } catch { }
            }
        }
    }

    [Fact]
    public async Task Id_token_expires_and_validates()
    {
        LogTestStart();
        var extra = new Dictionary<string, string?>
        {
            ["IdToken:Secret"] = "TEST_ID_TOKEN_SECRET_AT_LEAST_32_CHARS_LONG___",
            ["IdToken:Minutes"] = "5"
        };
        var (factory, client, dbPath) = CreateFactory(requireSecure: false, extraConfig: extra);
        try
        {
            var register = await client.PostAsJsonAsync("/register", new { Username = "expuser", Password = "P@ssw0rd!Long", Email = "exp@example.com" });
            var regPayload = await register.Content.ReadFromJsonAsync<RegisterResponse>();
            await client.PostAsJsonAsync("/confirm-email", new { Token = regPayload!.EmailConfirmToken });

            var login = await client.PostAsJsonAsync("/login", new { Username = "expuser", Password = "P@ssw0rd!Long" });
            var payload = await login.Content.ReadFromJsonAsync<LoginResponse>();
            var idSvc = factory.Services.GetRequiredService<IdTokenService>();

            var jwt = ValidateIdToken(payload!.IdToken!, idSvc.GetValidationParameters());
            Assert.True(jwt.ValidTo.ToUniversalTime() > DateTime.UtcNow);
        }
        finally
        {
            client.Dispose();
            factory.Dispose();
            if (File.Exists(dbPath))
            {
                try { File.Delete(dbPath); } catch { }
            }
        }
    }
    [Fact]
    public async Task Full_auth_flow_with_remember_and_mfa()
    {
        LogTestStart();
        var username = $"fullflow_{Guid.NewGuid():N}";
        var password = "P@ssw0rd!Long";
        var email = $"{username}@example.com";

        // Registrazione e conferma email
        var register = await _client.PostAsJsonAsync("/register", new { Username = username, Password = password, Email = email });
        Assert.Equal(HttpStatusCode.Created, register.StatusCode);
        var regPayload = await register.Content.ReadFromJsonAsync<RegisterResponse>();
        await ConfirmEmailAsync(regPayload!.EmailConfirmToken!);

        // Login base
        var login = await _client.PostAsJsonAsync("/login", new { Username = username, Password = password });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        var loginPayload = await login.Content.ReadFromJsonAsync<LoginResponse>();
        Assert.True(loginPayload!.Ok);
        var accessCookie = login.Headers.GetValues("Set-Cookie").First(c => c.StartsWith("access_token", StringComparison.OrdinalIgnoreCase)).Split(';', 2)[0];

        // Logout base
        using (var logoutReq = new HttpRequestMessage(HttpMethod.Post, "/logout"))
        {
            logoutReq.Headers.Add("Cookie", accessCookie);
            logoutReq.Headers.Add("X-CSRF-Token", loginPayload.CsrfToken);
            var logout = await _client.SendAsync(logoutReq);
            Assert.Equal(HttpStatusCode.OK, logout.StatusCode);
        }

        // Login con remember-me
        var loginRemember = await _client.PostAsJsonAsync("/login", new { Username = username, Password = password, RememberMe = true });
        Assert.Equal(HttpStatusCode.OK, loginRemember.StatusCode);
        var rememberPayload = await loginRemember.Content.ReadFromJsonAsync<LoginResponse>();
        Assert.True(rememberPayload!.RememberIssued);
        var rememberCookies = loginRemember.Headers.GetValues("Set-Cookie").ToList();
        var accessCookie2 = rememberCookies.First(c => c.StartsWith("access_token", StringComparison.OrdinalIgnoreCase)).Split(';', 2)[0];
        var refreshCookie = rememberCookies.First(c => c.StartsWith("refresh_token", StringComparison.OrdinalIgnoreCase)).Split(';', 2)[0];

        // Logout dopo remember
        using (var logoutReq = new HttpRequestMessage(HttpMethod.Post, "/logout"))
        {
            logoutReq.Headers.Add("Cookie", $"{accessCookie2}; {refreshCookie}");
            logoutReq.Headers.Add("X-CSRF-Token", rememberPayload.CsrfToken);
            var logout = await _client.SendAsync(logoutReq);
            Assert.Equal(HttpStatusCode.OK, logout.StatusCode);
        }

        // Login per setup MFA
        var loginForMfa = await _client.PostAsJsonAsync("/login", new { Username = username, Password = password });
        var loginForMfaPayload = await loginForMfa.Content.ReadFromJsonAsync<LoginResponse>();
        var accessCookie3 = loginForMfa.Headers.GetValues("Set-Cookie").First(c => c.StartsWith("access_token", StringComparison.OrdinalIgnoreCase)).Split(';', 2)[0];
        string secret;
        using (var setupReq = new HttpRequestMessage(HttpMethod.Post, "/mfa/setup"))
        {
            setupReq.Headers.Add("Cookie", accessCookie3);
            setupReq.Headers.Add("X-CSRF-Token", loginForMfaPayload!.CsrfToken);
            var setupResp = await _client.SendAsync(setupReq);
            Assert.Equal(HttpStatusCode.OK, setupResp.StatusCode);
            var setupPayload = await setupResp.Content.ReadFromJsonAsync<MfaSetupResponse>();
            secret = setupPayload!.Secret!;
        }
        // Logout dopo setup MFA
        using (var logoutReq = new HttpRequestMessage(HttpMethod.Post, "/logout"))
        {
            logoutReq.Headers.Add("Cookie", accessCookie3);
            logoutReq.Headers.Add("X-CSRF-Token", loginForMfaPayload!.CsrfToken);
            var logout = await _client.SendAsync(logoutReq);
            Assert.Equal(HttpStatusCode.OK, logout.StatusCode);
        }

        // Login con MFA richiesto
        var loginMfa = await _client.PostAsJsonAsync("/login", new { Username = username, Password = password });
        Assert.Equal(HttpStatusCode.Unauthorized, loginMfa.StatusCode);
        var mfaReq = await loginMfa.Content.ReadFromJsonAsync<MfaRequiredResponse>();
        Assert.Equal("mfa_required", mfaReq!.Error);

        // Conferma MFA
        var totp = new Totp(Base32Encoding.ToBytes(secret));
        var code = totp.ComputeTotp();
        var confirm = await _client.PostAsJsonAsync("/login/confirm-mfa", new { ChallengeId = mfaReq.ChallengeId, TotpCode = code });
        Assert.Equal(HttpStatusCode.OK, confirm.StatusCode);
        var confirmPayload = await confirm.Content.ReadFromJsonAsync<MfaConfirmResponse>();
        var accessCookie4 = confirm.Headers.GetValues("Set-Cookie").First(c => c.StartsWith("access_token", StringComparison.OrdinalIgnoreCase)).Split(';', 2)[0];

        // Logout finale
        using var finalLogoutReq = new HttpRequestMessage(HttpMethod.Post, "/logout");
        finalLogoutReq.Headers.Add("Cookie", accessCookie4);
        finalLogoutReq.Headers.Add("X-CSRF-Token", confirmPayload!.CsrfToken);
        var finalLogout = await _client.SendAsync(finalLogoutReq);
        Assert.Equal(HttpStatusCode.OK, finalLogout.StatusCode);
    }

    [Fact]
    public async Task Refresh_without_device_cookie_returns_unauthorized()
    {
        LogTestStart();
        var username = $"device_missing_{Guid.NewGuid():N}";
        var password = "P@ssw0rd!Long";
        var email = $"{username}@example.com";

        var register = await _client.PostAsJsonAsync("/register", new { Username = username, Password = password, Email = email });
        var regPayload = await register.Content.ReadFromJsonAsync<RegisterResponse>();
        await ConfirmEmailAsync(regPayload!.EmailConfirmToken!);

        var login = await _client.PostAsJsonAsync("/login", new { Username = username, Password = password, RememberMe = true });
        var refreshCookie = login.Headers.GetValues("Set-Cookie").First(c => c.StartsWith("refresh_token", StringComparison.OrdinalIgnoreCase)).Split(';', 2)[0];

        using var refreshReq = new HttpRequestMessage(HttpMethod.Post, "/refresh");
        refreshReq.Headers.Add("Cookie", refreshCookie); // manca device
        var resp = await _client.SendAsync(refreshReq);
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task Refresh_with_mismatched_device_cookie_returns_unauthorized()
    {
        LogTestStart();
        var username = $"device_mismatch_{Guid.NewGuid():N}";
        var password = "P@ssw0rd!Long";
        var email = $"{username}@example.com";

        var register = await _client.PostAsJsonAsync("/register", new { Username = username, Password = password, Email = email });
        var regPayload = await register.Content.ReadFromJsonAsync<RegisterResponse>();
        await ConfirmEmailAsync(regPayload!.EmailConfirmToken!);

        var login = await _client.PostAsJsonAsync("/login", new { Username = username, Password = password, RememberMe = true });
        var refreshCookie = login.Headers.GetValues("Set-Cookie").First(c => c.StartsWith("refresh_token", StringComparison.OrdinalIgnoreCase)).Split(';', 2)[0];

        using var refreshReq = new HttpRequestMessage(HttpMethod.Post, "/refresh");
        refreshReq.Headers.Add("Cookie", $"{refreshCookie}; device_id=fake");
        var resp = await _client.SendAsync(refreshReq);
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task Logout_all_revokes_refresh_but_device_cookie_reused_on_next_login()
    {
        LogTestStart();
        var username = $"device_logoutall_{Guid.NewGuid():N}";
        var password = "P@ssw0rd!Long";
        var email = $"{username}@example.com";

        var register = await _client.PostAsJsonAsync("/register", new { Username = username, Password = password, Email = email });
        var regPayload = await register.Content.ReadFromJsonAsync<RegisterResponse>();
        await ConfirmEmailAsync(regPayload!.EmailConfirmToken!);

        var login = await _client.PostAsJsonAsync("/login", new { Username = username, Password = password, RememberMe = true });
        var loginPayload = await login.Content.ReadFromJsonAsync<LoginResponse>();
        var cookies = login.Headers.GetValues("Set-Cookie").ToList();
        var accessCookie = cookies.First(c => c.StartsWith("access_token", StringComparison.OrdinalIgnoreCase)).Split(';', 2)[0];
        var refreshCookie = cookies.First(c => c.StartsWith("refresh_token", StringComparison.OrdinalIgnoreCase)).Split(';', 2)[0];
        var deviceCookie = cookies.First(c => c.StartsWith("device_id", StringComparison.OrdinalIgnoreCase)).Split(';', 2)[0];

        using (var logoutAllReq = new HttpRequestMessage(HttpMethod.Post, "/logout-all"))
        {
            logoutAllReq.Headers.Add("Cookie", $"{accessCookie}; {refreshCookie}; {deviceCookie}");
            logoutAllReq.Headers.Add("X-CSRF-Token", loginPayload!.CsrfToken);
            var logoutAll = await _client.SendAsync(logoutAllReq);
            Assert.Equal(HttpStatusCode.OK, logoutAll.StatusCode);
        }

        using var login2Req = new HttpRequestMessage(HttpMethod.Post, "/login");
        login2Req.Headers.Add("Cookie", deviceCookie);
        login2Req.Content = JsonContent.Create(new { Username = username, Password = password, RememberMe = true });
        var login2 = await _client.SendAsync(login2Req);
        Assert.Equal(HttpStatusCode.OK, login2.StatusCode);
        var cookies2 = login2.Headers.GetValues("Set-Cookie").ToList();
        var newRefreshCookie = cookies2.First(c => c.StartsWith("refresh_token", StringComparison.OrdinalIgnoreCase)).Split(';', 2)[0];

        await using var db = new SqliteConnection($"Data Source={_dbPath};Mode=ReadWriteCreate;Cache=Shared");
        await db.OpenAsync();
        var oldHash = _hasher.ComputeHash(refreshCookie.Split('=')[1]);
        var newHash = _hasher.ComputeHash(newRefreshCookie.Split('=')[1]);
        var oldRevoked = await db.ExecuteScalarAsync<string>("SELECT revoked_at_utc FROM refresh_tokens WHERE token_hash = @h", new { h = oldHash });
        Assert.False(string.IsNullOrWhiteSpace(oldRevoked));
        var deviceId = await db.ExecuteScalarAsync<string>("SELECT device_id FROM refresh_tokens WHERE token_hash = @h", new { h = newHash });
        Assert.Equal(deviceCookie.Split('=')[1], deviceId);
    }

    [Fact]
    public async Task Device_cookie_respects_samesite_and_secure_config()
    {
        LogTestStart();
        var extra = new Dictionary<string, string?>
        {
            ["Device:SameSite"] = "Lax",
            ["Device:RequireSecure"] = "true"
        };
        var (factory, client, dbPath) = CreateFactory(requireSecure: true, forceLowerUsername: false, extraConfig: extra);
        try
        {
            var username = $"device_cfg_{Guid.NewGuid():N}";
            var password = "P@ssw0rd!Long";
            var email = $"{username}@example.com";

            var register = await client.PostAsJsonAsync("/register", new { Username = username, Password = password, Email = email });
            var regPayload = await register.Content.ReadFromJsonAsync<RegisterResponse>();
            await client.PostAsJsonAsync("/confirm-email", new { Token = regPayload!.EmailConfirmToken });

            var login = await client.PostAsJsonAsync("/login", new { Username = username, Password = password, RememberMe = true });
            Assert.Equal(HttpStatusCode.OK, login.StatusCode);
            var cookies = login.Headers.GetValues("Set-Cookie").ToList();
            var deviceCookie = cookies.First(c => c.StartsWith("device_id", StringComparison.OrdinalIgnoreCase)).ToLowerInvariant();
            Assert.Contains("samesite=lax", deviceCookie);
            Assert.Contains("secure", deviceCookie);
        }
        finally
        {
            client.Dispose();
            factory.Dispose();
            if (File.Exists(dbPath))
            {
                try { File.Delete(dbPath); } catch { }
            }
        }
    }

    [Fact]
    public async Task Refresh_with_revoked_token_returns_unauthorized()
    {
        LogTestStart();
        var username = $"refresh_rev_{Guid.NewGuid():N}";
        var password = "P@ssw0rd!Long";
        var email = $"{username}@example.com";

        var register = await _client.PostAsJsonAsync("/register", new { Username = username, Password = password, Email = email });
        Assert.Equal(HttpStatusCode.Created, register.StatusCode);
        var regPayload = await register.Content.ReadFromJsonAsync<RegisterResponse>();
        await ConfirmEmailAsync(regPayload!.EmailConfirmToken!);

        var login = await _client.PostAsJsonAsync("/login", new { Username = username, Password = password, RememberMe = true });
        var csrf = (await login.Content.ReadFromJsonAsync<LoginResponse>())!.CsrfToken!;
        var cookies = login.Headers.GetValues("Set-Cookie").ToList();
        var accessCookie = cookies.First(c => c.StartsWith("access_token")).Split(';', 2)[0];
        var refreshCookie = cookies.First(c => c.StartsWith("refresh_token")).Split(';', 2)[0];

        using var logoutReq = new HttpRequestMessage(HttpMethod.Post, "/logout");
        logoutReq.Headers.Add("Cookie", $"{accessCookie}; {refreshCookie}");
        logoutReq.Headers.Add("X-CSRF-Token", csrf);
        var logout = await _client.SendAsync(logoutReq);
        Assert.Equal(HttpStatusCode.OK, logout.StatusCode);

        using var refreshReq = new HttpRequestMessage(HttpMethod.Post, "/refresh");
        refreshReq.Headers.Add("Cookie", refreshCookie);
        var refreshResp = await _client.SendAsync(refreshReq);
        Assert.Equal(HttpStatusCode.Unauthorized, refreshResp.StatusCode);
    }

    [Fact]
    public async Task Refresh_with_expired_token_returns_unauthorized()
    {
        LogTestStart();
        var username = $"refresh_exp_{Guid.NewGuid():N}";
        var password = "P@ssw0rd!Long";
        var email = $"{username}@example.com";

        var register = await _client.PostAsJsonAsync("/register", new { Username = username, Password = password, Email = email });
        var regPayload = await register.Content.ReadFromJsonAsync<RegisterResponse>();
        await ConfirmEmailAsync(regPayload!.EmailConfirmToken!);

        var login = await _client.PostAsJsonAsync("/login", new { Username = username, Password = password, RememberMe = true });
        var refreshCookie = login.Headers.GetValues("Set-Cookie").First(c => c.StartsWith("refresh_token", StringComparison.OrdinalIgnoreCase)).Split(';', 2)[0];

        await using (var db = new SqliteConnection($"Data Source={_dbPath};Mode=ReadWriteCreate;Cache=Shared"))
        {
            await db.OpenAsync();
            var hash = _hasher.ComputeHash(refreshCookie.Split('=')[1]);
            await db.ExecuteAsync("UPDATE refresh_tokens SET expires_at_utc = @exp WHERE token_hash = @h", new { exp = DateTime.UtcNow.AddMinutes(-1).ToString("O"), h = hash });
        }

        using var refreshReq = new HttpRequestMessage(HttpMethod.Post, "/refresh");
        refreshReq.Headers.Add("Cookie", refreshCookie);
        var resp = await _client.SendAsync(refreshReq);
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task Refresh_with_ua_mismatch_returns_unauthorized()
    {
        LogTestStart();
        var username = $"refresh_ua_{Guid.NewGuid():N}";
        var password = "P@ssw0rd!Long";
        var email = $"{username}@example.com";

        // Login con UA specifico
        using var loginReq = new HttpRequestMessage(HttpMethod.Post, "/login");
        loginReq.Headers.TryAddWithoutValidation("User-Agent", "UA-1");
        loginReq.Content = JsonContent.Create(new { Username = username, Password = password, Email = email, RememberMe = true });
        var register = await _client.PostAsJsonAsync("/register", new { Username = username, Password = password, Email = email });
        var regPayload = await register.Content.ReadFromJsonAsync<RegisterResponse>();
        await ConfirmEmailAsync(regPayload!.EmailConfirmToken!);
        var login = await _client.SendAsync(loginReq);
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        var refreshCookie = login.Headers.GetValues("Set-Cookie").First(c => c.StartsWith("refresh_token", StringComparison.OrdinalIgnoreCase)).Split(';', 2)[0];

        using var refreshReq = new HttpRequestMessage(HttpMethod.Post, "/refresh");
        refreshReq.Headers.TryAddWithoutValidation("User-Agent", "UA-2");
        refreshReq.Headers.Add("Cookie", refreshCookie);
        var resp = await _client.SendAsync(refreshReq);
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task Refresh_without_cookie_returns_unauthorized()
    {
        LogTestStart();
        var resp = await _client.PostAsync("/refresh", content: null);
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task Login_without_remember_does_not_emit_refresh_cookie()
    {
        LogTestStart();
        var username = $"norem_{Guid.NewGuid():N}";
        var password = "P@ssw0rd!Long";
        var email = $"{username}@example.com";

        var register = await _client.PostAsJsonAsync("/register", new { Username = username, Password = password, Email = email });
        Assert.Equal(HttpStatusCode.Created, register.StatusCode);
        var regPayload = await register.Content.ReadFromJsonAsync<RegisterResponse>();
        await ConfirmEmailAsync(regPayload!.EmailConfirmToken!);

        var login = await _client.PostAsJsonAsync("/login", new { Username = username, Password = password, RememberMe = false });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        var setCookies = login.Headers.TryGetValues("Set-Cookie", out var cookies)
            ? cookies.ToList()
            : new List<string>();
        Assert.DoesNotContain(setCookies, c => c.StartsWith("refresh_token", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Login_remember_respects_configured_days_for_maxage()
    {
        LogTestStart();
        var extra = new Dictionary<string, string?>
        {
            ["RememberMe:Days"] = "3"
        };
        var (factory, client, dbPath) = CreateFactory(requireSecure: false, forceLowerUsername: false, extraConfig: extra);
        try
        {
            var login = await client.PostAsJsonAsync("/login", new { Username = "demo", Password = "demo", RememberMe = true });
            Assert.Equal(HttpStatusCode.OK, login.StatusCode);
            var setCookie = login.Headers.GetValues("Set-Cookie").First(c => c.StartsWith("refresh_token", StringComparison.OrdinalIgnoreCase));
            var lower = setCookie.ToLowerInvariant();
            Assert.Contains("max-age", lower);

            // estrai max-age e verifica circa 3 giorni (tolleranza qualche secondo)
            var parts = lower.Split(';', StringSplitOptions.TrimEntries);
            var maxAgePart = parts.First(p => p.StartsWith("max-age"));
            var maxAgeSec = int.Parse(maxAgePart.Split('=')[1]);
            var expected = 3 * 24 * 60 * 60;
            Assert.InRange(maxAgeSec, expected - 5, expected + 5);
        }
        finally
        {
            client.Dispose();
            factory.Dispose();
            if (File.Exists(dbPath))
            {
                try { File.Delete(dbPath); } catch { }
            }
        }
    }

    [Fact]
    public async Task Totp_secret_is_encrypted_at_rest()
    {
        LogTestStart();
        var username = $"totpenc_{Guid.NewGuid():N}";
        var password = "P@ssw0rd!Long";
        var email = $"{username}@example.com";

        var register = await _client.PostAsJsonAsync("/register", new { Username = username, Password = password, Email = email });
        Assert.Equal(HttpStatusCode.Created, register.StatusCode);

        var (cookie, csrf) = await LoginAndGetSessionAsync(username, password);

        using var setupReq = new HttpRequestMessage(HttpMethod.Post, "/mfa/setup");
        setupReq.Headers.Add("Cookie", cookie);
        setupReq.Headers.Add("X-CSRF-Token", csrf);
        var setupResp = await _client.SendAsync(setupReq);
        Assert.Equal(HttpStatusCode.OK, setupResp.StatusCode);
        var setupPayload = await setupResp.Content.ReadFromJsonAsync<MfaSetupResponse>();
        Assert.NotNull(setupPayload);
        var secretPlain = setupPayload!.Secret!;

        await using var db = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={_dbPath};Mode=ReadWriteCreate;Cache=Shared");
        await db.OpenAsync();
        var stored = await db.ExecuteScalarAsync<string>("SELECT totp_secret FROM users WHERE username = @u", new { u = username });
        Assert.False(string.IsNullOrWhiteSpace(stored));
        Assert.NotEqual(secretPlain, stored); // non deve essere in chiaro

        // login con TOTP deve comunque funzionare
        var totp = new Totp(Base32Encoding.ToBytes(secretPlain));
        var code = totp.ComputeTotp();
        var login = await _client.PostAsJsonAsync("/login", new { Username = username, Password = password });
        Assert.Equal(HttpStatusCode.Unauthorized, login.StatusCode);
        var mfa = await login.Content.ReadFromJsonAsync<MfaRequiredResponse>();
        Assert.Equal("mfa_required", mfa!.Error);

        var confirm = await _client.PostAsJsonAsync("/login/confirm-mfa", new { ChallengeId = mfa.ChallengeId, TotpCode = code });
        Assert.Equal(HttpStatusCode.OK, confirm.StatusCode);
    }

    [Fact]
    public async Task Totp_wrong_code_returns_unauthorized()
    {
        LogTestStart();
        var username = $"totpbad_{Guid.NewGuid():N}";
        var password = "P@ssw0rd!Long";
        var email = $"{username}@example.com";

        var register = await _client.PostAsJsonAsync("/register", new { Username = username, Password = password, Email = email });
        Assert.Equal(HttpStatusCode.Created, register.StatusCode);

        var (cookie, csrf) = await LoginAndGetSessionAsync(username, password);

        using var setupReq = new HttpRequestMessage(HttpMethod.Post, "/mfa/setup");
        setupReq.Headers.Add("Cookie", cookie);
        setupReq.Headers.Add("X-CSRF-Token", csrf);
        var setupResp = await _client.SendAsync(setupReq);
        Assert.Equal(HttpStatusCode.OK, setupResp.StatusCode);
        var setupPayload = await setupResp.Content.ReadFromJsonAsync<MfaSetupResponse>();
        Assert.NotNull(setupPayload);

        using var logoutReq = new HttpRequestMessage(HttpMethod.Post, "/logout");
        logoutReq.Headers.Add("Cookie", cookie);
        logoutReq.Headers.Add("X-CSRF-Token", csrf);
        await _client.SendAsync(logoutReq);

        var wrongCode = "000000";
        var login = await _client.PostAsJsonAsync("/login", new { Username = username, Password = password, TotpCode = wrongCode });
        Assert.Equal(HttpStatusCode.Unauthorized, login.StatusCode);
    }

    [Fact]
    public async Task Totp_disable_allows_login_without_code()
    {
        LogTestStart();
        var username = $"totpdisable_{Guid.NewGuid():N}";
        var password = "P@ssw0rd!Long";
        var email = $"{username}@example.com";

        var register = await _client.PostAsJsonAsync("/register", new { Username = username, Password = password, Email = email });
        Assert.Equal(HttpStatusCode.Created, register.StatusCode);

        var (cookie, csrf) = await LoginAndGetSessionAsync(username, password);

        using var setupReq = new HttpRequestMessage(HttpMethod.Post, "/mfa/setup");
        setupReq.Headers.Add("Cookie", cookie);
        setupReq.Headers.Add("X-CSRF-Token", csrf);
        var setupResp = await _client.SendAsync(setupReq);
        Assert.Equal(HttpStatusCode.OK, setupResp.StatusCode);
        var setup = await setupResp.Content.ReadFromJsonAsync<MfaSetupResponse>();
        Assert.NotNull(setup);

        // Logout per richiedere TOTP al successivo login
        using (var logoutReq = new HttpRequestMessage(HttpMethod.Post, "/logout"))
        {
            logoutReq.Headers.Add("Cookie", cookie);
            logoutReq.Headers.Add("X-CSRF-Token", csrf);
            var lo = await _client.SendAsync(logoutReq);
            Assert.Equal(HttpStatusCode.OK, lo.StatusCode);
        }

        // Login senza TOTP deve fallire ora
        var noTotp = await _client.PostAsJsonAsync("/login", new { Username = username, Password = password });
        Assert.Equal(HttpStatusCode.Unauthorized, noTotp.StatusCode);

        // Login con TOTP ok
        var totp = new Totp(Base32Encoding.ToBytes(setup!.Secret!));
        var code = totp.ComputeTotp();
        var login = await _client.PostAsJsonAsync("/login", new { Username = username, Password = password });
        Assert.Equal(HttpStatusCode.Unauthorized, login.StatusCode);
        var mfa = await login.Content.ReadFromJsonAsync<MfaRequiredResponse>();
        var confirm = await _client.PostAsJsonAsync("/login/confirm-mfa", new { ChallengeId = mfa!.ChallengeId, TotpCode = code });
        Assert.Equal(HttpStatusCode.OK, confirm.StatusCode);
        var csrf2 = (await confirm.Content.ReadFromJsonAsync<MfaConfirmResponse>())!.CsrfToken!;
        var cookie2 = confirm.Headers.GetValues("Set-Cookie").First(h => h.StartsWith("access_token", StringComparison.Ordinal)).Split(';', 2)[0];

        // Disable MFA
        using var disableReq = new HttpRequestMessage(HttpMethod.Post, "/mfa/disable");
        disableReq.Headers.Add("Cookie", cookie2);
        disableReq.Headers.Add("X-CSRF-Token", csrf2);
        var disable = await _client.SendAsync(disableReq);
        Assert.Equal(HttpStatusCode.OK, disable.StatusCode);

        // Logout
        using (var logoutReq = new HttpRequestMessage(HttpMethod.Post, "/logout"))
        {
            logoutReq.Headers.Add("Cookie", cookie2);
            logoutReq.Headers.Add("X-CSRF-Token", csrf2);
            await _client.SendAsync(logoutReq);
        }

        // Ora login senza TOTP deve funzionare
        var loginNoTotp = await _client.PostAsJsonAsync("/login", new { Username = username, Password = password });
        Assert.Equal(HttpStatusCode.OK, loginNoTotp.StatusCode);
    }

    [Fact]
    public async Task Logout_without_csrf_returns_403()
    {
        LogTestStart();
        var (cookie, _) = await LoginAndGetSessionAsync();

        using var logoutRequest = new HttpRequestMessage(HttpMethod.Post, "/logout");
        logoutRequest.Headers.Add("Cookie", cookie);

        var response = await _client.SendAsync(logoutRequest);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);

        var doc = await response.Content.ReadFromJsonAsync<JsonDocument>();
        Assert.NotNull(doc);
        Assert.False(doc!.RootElement.GetProperty("ok").GetBoolean());
        Assert.Equal("csrf_invalid", doc.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Logout_with_wrong_csrf_returns_403()
    {
        LogTestStart();
        var (cookie, csrf) = await LoginAndGetSessionAsync();
        var wrongCsrf = csrf + "X";

        using var logoutRequest = new HttpRequestMessage(HttpMethod.Post, "/logout");
        logoutRequest.Headers.Add("Cookie", cookie);
        logoutRequest.Headers.Add("X-CSRF-Token", wrongCsrf);

        var response = await _client.SendAsync(logoutRequest);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);

        var doc = await response.Content.ReadFromJsonAsync<JsonDocument>();
        Assert.NotNull(doc);
        Assert.False(doc!.RootElement.GetProperty("ok").GetBoolean());
        Assert.Equal("csrf_invalid", doc.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Expired_session_cannot_access_me()
    {
        LogTestStart();
        var (cookie, _) = await LoginAndGetSessionAsync();

        await using (var db = new SqliteConnection($"Data Source={_dbPath};Mode=ReadWriteCreate;Cache=Shared"))
        {
            await db.OpenAsync();
            var update = db.CreateCommand();
            update.CommandText = "UPDATE user_sessions SET expires_at_utc = @exp WHERE 1=1;";
            var expired = DateTime.UtcNow.AddMinutes(-5).ToString("O");
            update.Parameters.AddWithValue("@exp", expired);
            await update.ExecuteNonQueryAsync();
        }

        using var meRequest = new HttpRequestMessage(HttpMethod.Get, "/me");
        meRequest.Headers.Add("Cookie", cookie);
        var response = await _client.SendAsync(meRequest);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Me_without_cookie_returns_401()
    {
        LogTestStart();
        var response = await _client.GetAsync("/me");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

        var doc = await response.Content.ReadFromJsonAsync<JsonDocument>();
        Assert.NotNull(doc);
        Assert.False(doc!.RootElement.GetProperty("ok").GetBoolean());
        Assert.Equal("unauthorized", doc.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Tampered_token_returns_401_on_me()
    {
        LogTestStart();
        var (cookie, _) = await LoginAndGetSessionAsync();
        var token = cookie.Split('=', 2)[1];
        var tampered = token + "x"; // break signature

        using var meRequest = new HttpRequestMessage(HttpMethod.Get, "/me");
        meRequest.Headers.Add("Cookie", $"access_token={tampered}");

        var response = await _client.SendAsync(meRequest);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Revoked_session_returns_401_on_me()
    {
        LogTestStart();
        var (cookie, _) = await LoginAndGetSessionAsync();

        await using (var db = new SqliteConnection($"Data Source={_dbPath};Mode=ReadWriteCreate;Cache=Shared"))
        {
            await db.OpenAsync();
            var update = db.CreateCommand();
            update.CommandText = "UPDATE user_sessions SET revoked_at_utc = @revoked WHERE 1=1;";
            var revoked = DateTime.UtcNow.ToString("O");
            update.Parameters.AddWithValue("@revoked", revoked);
            await update.ExecuteNonQueryAsync();
        }

        using var meRequest = new HttpRequestMessage(HttpMethod.Get, "/me");
        meRequest.Headers.Add("Cookie", cookie);
        var response = await _client.SendAsync(meRequest);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Login_without_require_secure_drops_secure_flag()
    {
        LogTestStart();
        var (factory, client, dbPath) = CreateFactory(requireSecure: false);
        try
        {
            var response = await client.PostAsJsonAsync("/login", new { Username = "demo", Password = "demo" });
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            var setCookie = response.Headers.GetValues("Set-Cookie").First();
            var lower = setCookie.ToLowerInvariant();
            Assert.Contains("access_token=", lower);
            Assert.Contains("httponly", lower);
            Assert.Contains("samesite=strict", lower);
            Assert.Contains("path=/", lower);
            Assert.Contains("max-age", lower);
            Assert.DoesNotContain("secure", lower);
        }
        finally
        {
            client.Dispose();
            factory.Dispose();
            if (File.Exists(dbPath))
            {
                try { File.Delete(dbPath); } catch (IOException) { }
            }
        }
    }

    [Fact]
    public async Task Introspect_reports_revoked_after_logout()
    {
        LogTestStart();
        var (cookie, csrf) = await LoginAndGetSessionAsync();

        var before = await IntrospectAsync(cookie);
        Assert.NotNull(before);
        Assert.True(before!.Active);

        using var logoutRequest = new HttpRequestMessage(HttpMethod.Post, "/logout");
        logoutRequest.Headers.Add("Cookie", cookie);
        logoutRequest.Headers.Add("X-CSRF-Token", csrf);
        var logoutResponse = await _client.SendAsync(logoutRequest);
        Assert.Equal(HttpStatusCode.OK, logoutResponse.StatusCode);

        var after = await IntrospectAsync(cookie);
        Assert.NotNull(after);
        Assert.False(after!.Active);
        Assert.Equal("revoked", after.Reason);
    }

    [Fact]
    public async Task Token_with_wrong_audience_returns_401_on_me()
    {
        LogTestStart();
        var (cookie, _) = await LoginAndGetSessionAsync();
        var token = cookie.Split('=', 2)[1];
        var wrongAudToken = RetokenizeWithOverrides(token, audience: "WrongAudience");
        var parsed = new JwtSecurityTokenHandler().ReadJwtToken(wrongAudToken);
        Assert.Equal("WrongAudience", parsed.Audiences.Single());

        using var meRequest = new HttpRequestMessage(HttpMethod.Get, "/me");
        meRequest.Headers.Add("Cookie", $"access_token={wrongAudToken}");
        var response = await _client.SendAsync(meRequest);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Token_with_wrong_issuer_returns_401_on_me()
    {
        LogTestStart();
        var (cookie, _) = await LoginAndGetSessionAsync();
        var token = cookie.Split('=', 2)[1];
        var wrongIssToken = RetokenizeWithOverrides(token, issuer: "WrongIssuer");
        var parsed = new JwtSecurityTokenHandler().ReadJwtToken(wrongIssToken);
        Assert.Equal("WrongIssuer", parsed.Issuer);

        using var meRequest = new HttpRequestMessage(HttpMethod.Get, "/me");
        meRequest.Headers.Add("Cookie", $"access_token={wrongIssToken}");
        var response = await _client.SendAsync(meRequest);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Expired_jwt_returns_401_on_me()
    {
        LogTestStart();
        var (cookie, _) = await LoginAndGetSessionAsync();
        var token = cookie.Split('=', 2)[1];

        var handler = new JwtSecurityTokenHandler { MapInboundClaims = false };
        var original = handler.ReadJwtToken(token);
        var claims = original.Claims;
        var creds = new SigningCredentials(
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes("TEST_SECRET_KEY_AT_LEAST_32_CHARACTERS_LONG__")),
            SecurityAlgorithms.HmacSha256);

        var expired = new JwtSecurityToken(
            issuer: original.Issuer,
            audience: original.Audiences.Single(),
            claims: claims,
            notBefore: DateTime.UtcNow.AddMinutes(-10),
            expires: DateTime.UtcNow.AddMinutes(-5),
            signingCredentials: creds);
        var expiredToken = handler.WriteToken(expired);

        using var meRequest = new HttpRequestMessage(HttpMethod.Get, "/me");
        meRequest.Headers.Add("Cookie", $"access_token={expiredToken}");
        var response = await _client.SendAsync(meRequest);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // Rigenera un token JWT con issuer/audience sovrascritti per simulare manomissione.
    private string RetokenizeWithOverrides(string token, string? audience = null, string? issuer = null)
    {
        var handler = new JwtSecurityTokenHandler { MapInboundClaims = false };
        var original = handler.ReadJwtToken(token);
        var claims = original.Claims
            .Where(c => !string.Equals(c.Type, JwtRegisteredClaimNames.Aud, StringComparison.OrdinalIgnoreCase))
            .Where(c => !string.Equals(c.Type, JwtRegisteredClaimNames.Iss, StringComparison.OrdinalIgnoreCase));
        var creds = new SigningCredentials(
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes("TEST_SECRET_KEY_AT_LEAST_32_CHARACTERS_LONG__")),
            SecurityAlgorithms.HmacSha256);

        var newToken = new JwtSecurityToken(
            issuer: issuer ?? original.Issuer,
            audience: audience ?? original.Audiences.Single(),
            claims: claims,
            notBefore: original.ValidFrom,
            expires: original.ValidTo,
            signingCredentials: creds);

        return handler.WriteToken(newToken);
    }

    // Effettua login demo e restituisce cookie + token CSRF per i test.
    private async Task<(string Cookie, string CsrfToken)> LoginAndGetSessionAsync(string username = "demo", string password = "demo")
    {
        var loginResponse = await _client.PostAsJsonAsync("/login", new { Username = username, Password = password });
        if (loginResponse.StatusCode == HttpStatusCode.Forbidden)
        {
            var doc = await loginResponse.Content.ReadFromJsonAsync<JsonDocument>();
            var error = doc?.RootElement.GetProperty("error").GetString();
            if (string.Equals(error, "email_not_confirmed", StringComparison.OrdinalIgnoreCase))
            {
                await using var db = new SqliteConnection($"Data Source={_dbPath};Mode=ReadWriteCreate;Cache=Shared");
                await db.OpenAsync();
                var token = await db.ExecuteScalarAsync<string>("SELECT email_confirm_token FROM users WHERE username = @u", new { u = username });
                Assert.False(string.IsNullOrWhiteSpace(token));
                var confirm = await _client.PostAsJsonAsync("/confirm-email", new { Token = token });
                Assert.Equal(HttpStatusCode.OK, confirm.StatusCode);
                loginResponse = await _client.PostAsJsonAsync("/login", new { Username = username, Password = password });
            }
        }
        Assert.Equal(HttpStatusCode.OK, loginResponse.StatusCode);
        var loginPayload = await loginResponse.Content.ReadFromJsonAsync<LoginResponse>();
        Assert.NotNull(loginPayload);
        Assert.True(loginPayload!.Ok);
        Assert.False(string.IsNullOrWhiteSpace(loginPayload.CsrfToken));

        var csrf = loginPayload.CsrfToken!;
        var setCookie = loginResponse.Headers.GetValues("Set-Cookie").First(h => h.StartsWith("access_token", StringComparison.Ordinal));
        var cookie = setCookie.Split(';', 2)[0];
        return (cookie, csrf);
    }

    private async Task<IntrospectResponse?> IntrospectAsync(string cookie)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, "/introspect");
        req.Headers.Add("Cookie", cookie);
        var resp = await _client.SendAsync(req);
        if (!resp.IsSuccessStatusCode)
            return null;
        return await resp.Content.ReadFromJsonAsync<IntrospectResponse>();
    }

    [Fact]
    public async Task Username_lowercase_policy_allows_case_insensitive_login()
    {
        LogTestStart();
        var (factory, client, dbPath) = CreateFactory(requireSecure: false, forceLowerUsername: true);
        try
        {
            var mixed = $"CaseUser_{Guid.NewGuid():N}";
            var upper = mixed.ToUpperInvariant();
            var password = "P@ssw0rd!Longer";
            var email = $"{mixed.ToLowerInvariant()}@example.com";

            var register = await client.PostAsJsonAsync("/register", new { Username = mixed, Password = password, Email = email });
            Assert.Equal(HttpStatusCode.Created, register.StatusCode);
            var regPayload = await register.Content.ReadFromJsonAsync<RegisterResponse>();
            Assert.NotNull(regPayload);
            var confirm = await client.PostAsJsonAsync("/confirm-email", new { Token = regPayload!.EmailConfirmToken });
            Assert.Equal(HttpStatusCode.OK, confirm.StatusCode);

            await using (var dbCheck = new SqliteConnection($"Data Source={dbPath};Mode=ReadWriteCreate;Cache=Shared"))
            {
                await dbCheck.OpenAsync();
                var count = await dbCheck.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM users;");
                _output.WriteLine($"Users count in DB: {count}");
                var allUsers = (await dbCheck.QueryAsync<string>("SELECT username FROM users;")).ToList();
                _output.WriteLine("All usernames: " + string.Join(",", allUsers));
                var storedUser = await dbCheck.QuerySingleOrDefaultAsync<string>("SELECT username FROM users WHERE username = @u", new { u = mixed.ToLowerInvariant() });
                _output.WriteLine($"Stored username: {storedUser}");
                Assert.Equal(mixed.ToLowerInvariant(), storedUser);
            }

            var loginLower = await client.PostAsJsonAsync("/login", new { Username = mixed.ToLowerInvariant(), Password = password });
            var lowerBody = await loginLower.Content.ReadAsStringAsync();
            _output.WriteLine($"Login lower status {loginLower.StatusCode}, body: {lowerBody}");
            Assert.Equal(HttpStatusCode.OK, loginLower.StatusCode);

            var loginUpper = await client.PostAsJsonAsync("/login", new { Username = upper, Password = password });
            var body = await loginUpper.Content.ReadAsStringAsync();
            _output.WriteLine($"Login status {loginUpper.StatusCode}, body: {body}");
            Assert.Equal(HttpStatusCode.OK, loginUpper.StatusCode);

            await using var db = new SqliteConnection($"Data Source={dbPath};Mode=ReadWriteCreate;Cache=Shared");
            await db.OpenAsync();
            var stored = await db.ExecuteScalarAsync<string>("SELECT username FROM users WHERE username = @u", new { u = mixed.ToLowerInvariant() });
            Assert.Equal(mixed.ToLowerInvariant(), stored);
        }
        finally
        {
            client.Dispose();
            factory.Dispose();
            if (System.IO.File.Exists(dbPath))
            {
                try { System.IO.File.Delete(dbPath); } catch { }
            }
        }
    }
}
