using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace SecureAuthClient;

/// <summary>
/// Client strongly-typed per gli endpoint di SecureAuthMinimalApi.
/// Gestisce automaticamente cookie, CSRF, refresh-CSRF e User-Agent.
/// </summary>
public sealed class SecureAuthApiClient : IDisposable
{
    private readonly HttpClient _http;
    private readonly CookieContainer _cookies;
    private readonly JsonSerializerOptions _jsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    private string? _csrfToken;
    private string? _refreshCsrfToken;

    public string? CsrfToken => _csrfToken;
    public string? RefreshCsrfToken => _refreshCsrfToken;
    public CookieContainer Cookies => _cookies;

    public SecureAuthApiClient(SecureAuthClientOptions options, HttpMessageHandler? handler = null)
    {
        _cookies = new CookieContainer();

        if (handler is null)
        {
            var h = new HttpClientHandler
            {
                CookieContainer = _cookies,
                UseCookies = true,
                AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate
            };
            handler = h;
        }

        _http = new HttpClient(handler)
        {
            BaseAddress = new Uri(options.BaseUrl),
            Timeout = options.Timeout
        };
        _http.DefaultRequestHeaders.UserAgent.ParseAdd(options.UserAgent);
        _http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
    }

    public async Task<LoginResult> LoginAsync(string username, string password, bool rememberMe = true, string? nonce = null)
    {
        var payload = new
        {
            username,
            password,
            rememberMe,
            nonce
        };

        var res = await PostJson<LoginResult>("/login", payload);
        UpdateTokens(res);
        return res;
    }

    public async Task<LoginResult> ConfirmMfaAsync(string challengeId, string totpCode, bool rememberMe = true, string? nonce = null)
    {
        var payload = new
        {
            challengeId,
            totpCode,
            rememberMe,
            nonce
        };

        var res = await PostJson<LoginResult>("/login/confirm-mfa", payload);
        UpdateTokens(res);
        return res;
    }

    public async Task<RefreshResult> RefreshAsync()
    {
        EnsureRefreshCsrf();
        var res = await PostJson<RefreshResult>("/refresh", new { }, includeRefreshCsrf: true);
        UpdateTokens(res);
        return res;
    }

    public async Task<ApiResult> LogoutAsync()
    {
        EnsureCsrf();
        var res = await PostJson<ApiResult>("/logout", new { }, includeCsrf: true);
        return res;
    }

    public async Task<ApiResult> LogoutAllAsync()
    {
        EnsureCsrf();
        var res = await PostJson<ApiResult>("/logout-all", new { }, includeCsrf: true);
        return res;
    }

    public async Task<MeResult?> MeAsync()
    {
        var response = await _http.GetAsync("/me");
        response.EnsureSuccessStatusCode();
        var content = await response.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<MeResult>(content, _jsonOptions);
    }

    public async Task<ApiResult> ChangeEmailAsync(string newEmail)
    {
        EnsureCsrf();
        var res = await PostJson<ApiResult>("/me/email", new { newEmail }, includeCsrf: true);
        return res;
    }

    public async Task<ApiResult> ChangePasswordAsync(string currentPassword, string newPassword, string confirmPassword)
    {
        EnsureCsrf();
        var res = await PostJson<ApiResult>("/me/password", new
        {
            currentPassword,
            newPassword,
            confirmPassword
        }, includeCsrf: true);
        return res;
    }

    public async Task<PasswordResetRequestResult> PasswordResetRequestAsync(string email)
    {
        var res = await PostJson<PasswordResetRequestResult>("/password-reset/request", new { email });
        return res;
    }

    public async Task<ApiResult> PasswordResetConfirmAsync(string token, string newPassword, string confirmPassword)
    {
        var res = await PostJson<ApiResult>("/password-reset/confirm", new
        {
            token,
            newPassword,
            confirmPassword
        });
        return res;
    }

    private async Task<T> PostJson<T>(string path, object payload, bool includeCsrf = false, bool includeRefreshCsrf = false)
    {
        using var req = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json")
        };

        if (includeCsrf)
        {
            req.Headers.Add("X-CSRF-Token", _csrfToken);
        }

        if (includeRefreshCsrf)
        {
            req.Headers.Add("X-Refresh-Csrf", _refreshCsrfToken);
        }

        var resp = await _http.SendAsync(req);
        resp.EnsureSuccessStatusCode();
        var content = await resp.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<T>(content, _jsonOptions)!;
    }

    private void UpdateTokens(LoginResult res)
    {
        if (!string.IsNullOrWhiteSpace(res.CsrfToken))
        {
            _csrfToken = res.CsrfToken;
        }
        if (!string.IsNullOrWhiteSpace(res.RefreshCsrfToken))
        {
            _refreshCsrfToken = res.RefreshCsrfToken;
        }
    }

    private void UpdateTokens(RefreshResult res)
    {
        if (!string.IsNullOrWhiteSpace(res.CsrfToken))
        {
            _csrfToken = res.CsrfToken;
        }
        if (!string.IsNullOrWhiteSpace(res.RefreshCsrfToken))
        {
            _refreshCsrfToken = res.RefreshCsrfToken;
        }
    }

    private void EnsureCsrf()
    {
        if (string.IsNullOrWhiteSpace(_csrfToken))
        {
            throw new InvalidOperationException("CSRF token non presente. Esegui un login/refresh prima di chiamare questo endpoint.");
        }
    }

    private void EnsureRefreshCsrf()
    {
        if (string.IsNullOrWhiteSpace(_refreshCsrfToken))
        {
            throw new InvalidOperationException("Refresh CSRF token non presente. Esegui login per ottenere refreshCsrfToken.");
        }
    }

    public void Dispose()
    {
        _http.Dispose();
    }
}

public sealed record ApiResult(bool Ok, string? Error, string? ErrorDescription = null);

public sealed record LoginResult(
    bool Ok,
    string? Error,
    string? CsrfToken,
    string? RefreshCsrfToken,
    string? ChallengeId,
    bool RememberIssued,
    bool DeviceIssued,
    string? DeviceId,
    string? RefreshExpiresAtUtc,
    string? IdToken);

public sealed record RefreshResult(
    bool Ok,
    string? Error,
    string? CsrfToken,
    string? RefreshCsrfToken,
    bool RememberIssued,
    bool DeviceIssued,
    string? DeviceId,
    string? RefreshExpiresAtUtc);

public sealed record MeResult(bool Ok, string? UserId, string? Username, string? Email, bool MfaConfirmed);

public sealed record PasswordResetRequestResult(bool Ok, string? ResetToken);
