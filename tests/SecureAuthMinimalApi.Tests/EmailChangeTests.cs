using System.Net;
using System.Net.Http.Json;
using Dapper;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace SecureAuthMinimalApi.Tests;

public class EmailChangeTests : IAsyncLifetime
{
    private WebApplicationFactory<Program> _factory = null!;
    private HttpClient _client = null!;
    private string _dbPath = null!;

    public Task InitializeAsync()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), $"email-change-{Guid.NewGuid():N}.db");
        _factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.UseSetting("environment", "Development");
                builder.ConfigureAppConfiguration((context, configBuilder) =>
                {
                    var overrides = new Dictionary<string, string?>
                    {
                        ["ConnectionStrings:Sqlite"] = $"Data Source={_dbPath};Mode=ReadWriteCreate;Cache=Shared",
                        ["EmailConfirmation:Required"] = "false",
                        ["Cookie:RequireSecure"] = "false",
                        ["PasswordReset:IncludeTokenInResponseForTesting"] = "true",
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
        return Task.CompletedTask;
    }

    public Task DisposeAsync()
    {
        _client.Dispose();
        _factory.Dispose();
        if (!string.IsNullOrWhiteSpace(_dbPath) && File.Exists(_dbPath))
        {
            try { File.Delete(_dbPath); } catch { }
        }
        return Task.CompletedTask;
    }

    private sealed record RegisterResponse(bool Ok, string? UserId, string? EmailConfirmToken, string? EmailConfirmExpiresUtc);
    private sealed record LoginResponse(bool Ok, string? CsrfToken);
    private sealed record ChangeEmailResponse(bool Ok, string? ConfirmToken, string? ConfirmExpiresUtc);

    [Fact]
    public async Task ChangeEmail_UnconfirmedUser_SucceedsAndGeneratesNewToken()
    {
        // Scenario: utente non confermato aggiorna l'email errata con una nuova e riceve un token di conferma.
        // Risultato atteso: email aggiornata in DB, email_confirmed=0, token e scadenza rigenerati.
        var oldEmail = $"old_{Guid.NewGuid():N}@example.com";
        var newEmail = $"new_{Guid.NewGuid():N}@example.com";
        var password = "EmailChange123!";

        var register = await _client.PostAsJsonAsync("/register", new { Email = oldEmail, Password = password, Username = oldEmail });
        Assert.Equal(HttpStatusCode.Created, register.StatusCode);
        var regPayload = await register.Content.ReadFromJsonAsync<RegisterResponse>();
        Assert.NotNull(regPayload);

        var login = await _client.PostAsJsonAsync("/login", new { Username = oldEmail, Password = password });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        var loginPayload = await login.Content.ReadFromJsonAsync<LoginResponse>();
        Assert.NotNull(loginPayload);
        var csrf = loginPayload!.CsrfToken!;
        var accessCookie = login.Headers.GetValues("Set-Cookie").First(c => c.StartsWith("access_token", StringComparison.OrdinalIgnoreCase)).Split(';', 2)[0];

        using var changeReq = new HttpRequestMessage(HttpMethod.Post, "/me/email")
        {
            Content = JsonContent.Create(new { NewEmail = newEmail })
        };
        changeReq.Headers.Add("Cookie", accessCookie);
        changeReq.Headers.Add("X-CSRF-Token", csrf);
        var change = await _client.SendAsync(changeReq);
        Assert.Equal(HttpStatusCode.OK, change.StatusCode);
        var changePayload = await change.Content.ReadFromJsonAsync<ChangeEmailResponse>();
        Assert.NotNull(changePayload);
        Assert.False(string.IsNullOrWhiteSpace(changePayload!.ConfirmToken));

        await using var db = new SqliteConnection($"Data Source={_dbPath};Mode=ReadWriteCreate;Cache=Shared");
        var row = await db.QuerySingleAsync<(string Email, string EmailNormalized, int EmailConfirmed, string ConfirmToken)>(
            "SELECT email, email_normalized, email_confirmed, email_confirm_token FROM users WHERE id = @id",
            new { id = regPayload!.UserId });

        Assert.Equal(newEmail, row.Email);
        Assert.Equal(newEmail.ToLowerInvariant(), row.EmailNormalized);
        Assert.Equal(0, row.EmailConfirmed);
        Assert.Equal(changePayload.ConfirmToken, row.ConfirmToken);
    }
}
