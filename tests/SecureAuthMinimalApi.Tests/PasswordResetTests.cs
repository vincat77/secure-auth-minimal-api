using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Dapper;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using SecureAuthMinimalApi.Models;
using Xunit;

namespace SecureAuthMinimalApi.Tests;

/// <summary>
/// Copertura minima del flusso reset password end-to-end: generazione token (solo in dev/test)
/// e conferma con cambio password. I test usano un DB SQLite temporaneo, configurazione in-memory
/// e bypassano cookie/redirect per restare focalizzati sulle API JSON.
/// </summary>
public class PasswordResetTests : IAsyncLifetime
{
    private WebApplicationFactory<Program> _factory = null!;
    private HttpClient _client = null!;
    private string _dbPath = null!;

    public Task InitializeAsync()
    {
        // Setup: crea un DB temporaneo e fornisce override di configurazione per
        // abilitare il token in risposta, evitare cookie Secure forzati e fissare
        // i segreti JWT/ID token per i test.
        _dbPath = Path.Combine(Path.GetTempPath(), $"reset-tests-{Guid.NewGuid():N}.db");
        _factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.UseSetting("environment", "Development");
                builder.ConfigureAppConfiguration((context, configBuilder) =>
                {
                    var overrides = new Dictionary<string, string?>
                    {
                        ["ConnectionStrings:Sqlite"] = $"Data Source={_dbPath};Mode=ReadWriteCreate;Cache=Shared",
                        ["PasswordReset:ExpirationMinutes"] = "30",
                        ["PasswordReset:RequireConfirmed"] = "true",
                        ["PasswordReset:IncludeTokenInResponseForTesting"] = "true",
                        ["PasswordReset:RetentionDays"] = "7",
                        ["Cookie:RequireSecure"] = "false",
                        ["EmailConfirmation:Required"] = "true",
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
        // Teardown: chiude il client/factory e rimuove il file SQLite temporaneo.
        _client.Dispose();
        _factory.Dispose();
        if (!string.IsNullOrWhiteSpace(_dbPath) && File.Exists(_dbPath))
        {
            try { File.Delete(_dbPath); } catch { }
        }
        return Task.CompletedTask;
    }

    private async Task<(string UserId, string Email, string Password, string ConfirmToken)> CreateUserAsync()
    {
        var email = $"reset_{Guid.NewGuid():N}@example.com";
        var password = "ResetPassword123!";
        var register = await _client.PostAsJsonAsync("/register", new { Email = email, Password = password, Username = email });
        Assert.Equal(HttpStatusCode.Created, register.StatusCode);
        var payload = await register.Content.ReadFromJsonAsync<RegisterResponse>();
        Assert.NotNull(payload);
        return (payload!.UserId!, email, password, payload.EmailConfirmToken!);
    }

    private record RegisterResponse(bool Ok, string? UserId, string? EmailConfirmToken, string? EmailConfirmExpiresUtc);
    private record ResetRequestResponse(bool Ok, string? ResetToken);

    [Fact]
    public async Task PasswordReset_Flow_Succeeds()
    {
        // Scenario: utente confermato richiede reset e completa il flusso con nuova password valida.
        // Risultato atteso: il token viene accettato, la password cambia e il login con vecchia password fallisce.
        var (userId, email, oldPassword, confirmToken) = await CreateUserAsync();
        var confirm = await _client.PostAsJsonAsync("/confirm-email", new { Token = confirmToken });
        Assert.Equal(HttpStatusCode.OK, confirm.StatusCode);

        var request = await _client.PostAsJsonAsync("/password-reset/request", new { Email = email });
        Assert.Equal(HttpStatusCode.OK, request.StatusCode);
        var reqPayload = await request.Content.ReadFromJsonAsync<ResetRequestResponse>();
        Assert.NotNull(reqPayload);
        Assert.False(string.IsNullOrWhiteSpace(reqPayload!.ResetToken));
        var resetToken = reqPayload.ResetToken!;

        var confirmReset = await _client.PostAsJsonAsync("/password-reset/confirm", new
        {
            Token = resetToken,
            NewPassword = "NewResetPassword456!",
            ConfirmPassword = "NewResetPassword456!"
        });
        Assert.Equal(HttpStatusCode.OK, confirmReset.StatusCode);

        // Old password should fail
        var loginOld = await _client.PostAsJsonAsync("/login", new { Username = email, Password = oldPassword });
        Assert.Equal(HttpStatusCode.Unauthorized, loginOld.StatusCode);

        // New password should succeed
        var loginNew = await _client.PostAsJsonAsync("/login", new { Username = email, Password = "NewResetPassword456!" });
        Assert.Equal(HttpStatusCode.OK, loginNew.StatusCode);
    }

    [Fact]
    public async Task PasswordReset_ExpiredToken_ReturnsInvalidToken()
    {
        // Scenario: utente confermato richiede reset ma il token viene retrodatato oltre la scadenza.
        // Risultato atteso: la conferma restituisce 400 invalid_token e la password rimane invariata.
        var (userId, email, _, confirmToken) = await CreateUserAsync();
        var confirm = await _client.PostAsJsonAsync("/confirm-email", new { Token = confirmToken });
        Assert.Equal(HttpStatusCode.OK, confirm.StatusCode);

        var request = await _client.PostAsJsonAsync("/password-reset/request", new { Email = email });
        Assert.Equal(HttpStatusCode.OK, request.StatusCode);
        var reqPayload = await request.Content.ReadFromJsonAsync<ResetRequestResponse>();
        var resetToken = reqPayload!.ResetToken!;

        await using (var db = new SqliteConnection($"Data Source={_dbPath};Mode=ReadWriteCreate;Cache=Shared"))
        {
            await db.OpenAsync();
            var hash = HashToken(resetToken);
            await db.ExecuteAsync("UPDATE password_resets SET expires_at_utc = datetime('now', '-1 hour') WHERE token_hash = @hash", new { hash });
        }

        var confirmReset = await _client.PostAsJsonAsync("/password-reset/confirm", new
        {
            Token = resetToken,
            NewPassword = "AnotherPassword789!",
            ConfirmPassword = "AnotherPassword789!"
        });
        Assert.Equal(HttpStatusCode.BadRequest, confirmReset.StatusCode);
        var body = await confirmReset.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("invalid_token", body!.GetProperty("error").GetString());
    }

    [Fact]
    public async Task PasswordReset_SecondConfirm_FailsWithInvalidToken()
    {
        // Scenario: token già usato viene confermato una seconda volta.
        // Risultato atteso: prima conferma OK, seconda 400 invalid_token; la nuova password resta valida.
        var (_, email, oldPassword, confirmToken) = await CreateUserAsync();
        var confirmEmail = await _client.PostAsJsonAsync("/confirm-email", new { Token = confirmToken });
        Assert.Equal(HttpStatusCode.OK, confirmEmail.StatusCode);

        var request = await _client.PostAsJsonAsync("/password-reset/request", new { Email = email });
        var resetToken = (await request.Content.ReadFromJsonAsync<ResetRequestResponse>())!.ResetToken!;

        var firstConfirm = await _client.PostAsJsonAsync("/password-reset/confirm", new
        {
            Token = resetToken,
            NewPassword = "FirstResetPwd!1",
            ConfirmPassword = "FirstResetPwd!1"
        });
        Assert.Equal(HttpStatusCode.OK, firstConfirm.StatusCode);

        var secondConfirm = await _client.PostAsJsonAsync("/password-reset/confirm", new
        {
            Token = resetToken,
            NewPassword = "SecondResetPwd!2",
            ConfirmPassword = "SecondResetPwd!2"
        });
        Assert.Equal(HttpStatusCode.BadRequest, secondConfirm.StatusCode);
        var body = await secondConfirm.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("invalid_token", body!.GetProperty("error").GetString());

        var loginOld = await _client.PostAsJsonAsync("/login", new { Username = email, Password = oldPassword });
        Assert.Equal(HttpStatusCode.Unauthorized, loginOld.StatusCode);
        var loginNew = await _client.PostAsJsonAsync("/login", new { Username = email, Password = "FirstResetPwd!1" });
        Assert.Equal(HttpStatusCode.OK, loginNew.StatusCode);
    }

    [Fact]
    public async Task PasswordReset_NewRequest_InvalidatesPreviousToken()
    {
        // Scenario: due richieste consecutive invalidano il primo token.
        // Risultato atteso: token1 diventa invalid_token, token2 funziona e cambia la password.
        var (_, email, _, confirmToken) = await CreateUserAsync();
        var confirmEmail = await _client.PostAsJsonAsync("/confirm-email", new { Token = confirmToken });
        Assert.Equal(HttpStatusCode.OK, confirmEmail.StatusCode);

        var req1 = await _client.PostAsJsonAsync("/password-reset/request", new { Email = email });
        var token1 = (await req1.Content.ReadFromJsonAsync<ResetRequestResponse>())!.ResetToken!;
        await Task.Delay(50); // differenzia i timestamp
        var req2 = await _client.PostAsJsonAsync("/password-reset/request", new { Email = email });
        var token2 = (await req2.Content.ReadFromJsonAsync<ResetRequestResponse>())!.ResetToken!;

        var confirmOld = await _client.PostAsJsonAsync("/password-reset/confirm", new
        {
            Token = token1,
            NewPassword = "TmpPassword!3",
            ConfirmPassword = "TmpPassword!3"
        });
        Assert.Equal(HttpStatusCode.BadRequest, confirmOld.StatusCode);

        var confirmNew = await _client.PostAsJsonAsync("/password-reset/confirm", new
        {
            Token = token2,
            NewPassword = "LatestPassword!4",
            ConfirmPassword = "LatestPassword!4"
        });
        Assert.Equal(HttpStatusCode.OK, confirmNew.StatusCode);

        var loginNew = await _client.PostAsJsonAsync("/login", new { Username = email, Password = "LatestPassword!4" });
        Assert.Equal(HttpStatusCode.OK, loginNew.StatusCode);
    }

    [Fact]
    public async Task PasswordReset_UnconfirmedAllowed_WhenRequireConfirmedFalse()
    {
        // Scenario: RequireConfirmed=false consente reset per email non confermate.
        // Risultato atteso: token creato e conferma riuscita per utente non confermato.
        var altDb = Path.Combine(Path.GetTempPath(), $"reset-tests-{Guid.NewGuid():N}.db");
        await using var factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.UseSetting("environment", "Development");
                builder.ConfigureAppConfiguration((context, configBuilder) =>
                {
                    var overrides = new Dictionary<string, string?>
                    {
                        ["ConnectionStrings:Sqlite"] = $"Data Source={altDb};Mode=ReadWriteCreate;Cache=Shared",
                        ["PasswordReset:ExpirationMinutes"] = "30",
                        ["PasswordReset:RequireConfirmed"] = "false",
                        ["PasswordReset:IncludeTokenInResponseForTesting"] = "true",
                        ["PasswordReset:RetentionDays"] = "7",
                        ["Cookie:RequireSecure"] = "false",
                        ["EmailConfirmation:Required"] = "true",
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
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            HandleCookies = false,
            AllowAutoRedirect = false
        });

        // Utente non confermato
        var email = $"reset_unconfirmed_{Guid.NewGuid():N}@example.com";
        var password = "ResetPassword123!";
        var register = await client.PostAsJsonAsync("/register", new { Email = email, Password = password, Username = email });
        Assert.Equal(HttpStatusCode.Created, register.StatusCode);

        var request = await client.PostAsJsonAsync("/password-reset/request", new { Email = email });
        Assert.Equal(HttpStatusCode.OK, request.StatusCode);
        var token = (await request.Content.ReadFromJsonAsync<ResetRequestResponse>())!.ResetToken!;
        Assert.False(string.IsNullOrWhiteSpace(token));

        var confirmReset = await client.PostAsJsonAsync("/password-reset/confirm", new
        {
            Token = token,
            NewPassword = "NewPassword999!",
            ConfirmPassword = "NewPassword999!"
        });
        Assert.Equal(HttpStatusCode.OK, confirmReset.StatusCode);

        var login = await client.PostAsJsonAsync("/login", new { Username = email, Password = "NewPassword999!" });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);

        client.Dispose();
        try { if (File.Exists(altDb)) File.Delete(altDb); } catch { }
    }

    private static string HashToken(string token)
    {
        using var sha = System.Security.Cryptography.SHA256.Create();
        var bytes = Encoding.UTF8.GetBytes(token);
        var hash = sha.ComputeHash(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
