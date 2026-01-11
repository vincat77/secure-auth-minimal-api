using System.Text.Json;
using SecureAuthClient;
using System.Text;
using System.Net.Http.Headers;

namespace WinFORM_AUTH_Client;

public partial class MainForm : Form
{
    private SecureAuthApiClient? _api;
    private HttpClient? _rawHttp;
    private HttpClientHandler? _handler;

    public MainForm()
    {
        InitializeComponent();
    }

    private async void btnRunFlow_Click(object sender, EventArgs e)
    {
        try
        {
            btnRunFlow.Enabled = false;
            txtLog.Clear();
            EnsureClient();
            await RunFlowAsync();
        }
        catch (Exception ex)
        {
            Log($"Errore: {ex.Message}");
        }
        finally
        {
            btnRunFlow.Enabled = true;
        }
    }

    private void EnsureClient()
    {
        if (_api != null) return;

        _handler = new HttpClientHandler
        {
            CookieContainer = new System.Net.CookieContainer(),
            UseCookies = true,
            AutomaticDecompression = System.Net.DecompressionMethods.GZip | System.Net.DecompressionMethods.Deflate,
            ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
        };

        _api = new SecureAuthApiClient(new SecureAuthClientOptions
        {
            BaseUrl = txtBaseUrl.Text.Trim(),
            UserAgent = "WinFORM_AUTH_Client/1.0"
        }, _handler);

        _rawHttp = new HttpClient(_handler)
        {
            BaseAddress = new Uri(txtBaseUrl.Text.Trim())
        };
        _rawHttp.DefaultRequestHeaders.UserAgent.ParseAdd("WinFORM_AUTH_Client/1.0");
        _rawHttp.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
    }

    private async Task RunFlowAsync()
    {
        if (_api == null) throw new InvalidOperationException("Api client non inizializzato");

        var username = $"flow-{Guid.NewGuid():N}".Substring(0, 16);
        var password = "FlowUser123!";
        var email = $"{username}@example.com";

        Log($"[Flow] Register {username}");
        var reg = await PostJson<RegisterResp>("/register", new { username, password, email });
        var confirmToken = reg?.EmailConfirmToken;
        Log($"[Flow] Confirm token: {confirmToken}");

        if (string.IsNullOrWhiteSpace(confirmToken))
        {
            Log("[Flow] Token conferma mancante, stop");
            return;
        }

        Log("[Flow] Confirm email");
        await PostJson<object>("/confirm-email", new { token = confirmToken.ToString() });

        Log("[Flow] Login password");
        var login = await _api.LoginAsync(username, password, rememberMe: true);
        if (!login.Ok && login.Error != "mfa_required")
        {
            Log($"[Flow] Login fallito: {login.Error}");
            return;
        }

        string? csrf = login.CsrfToken;
        string? refreshCsrf = login.RefreshCsrfToken;

        Log("[Flow] Setup MFA");
        if (string.IsNullOrWhiteSpace(csrf))
        {
            Log("[Flow] CSRF mancante dopo login, stop");
            return;
        }

        var setup = await PostJson<MfaSetupResponse>("/mfa/setup", new { }, csrfHeader: csrf);
        if (setup is null || string.IsNullOrWhiteSpace(setup.Secret))
        {
            Log("[Flow] Setup MFA senza secret, stop");
            return;
        }

        txtOtpauth.Text = setup.OtpauthUri ?? "";
        Log($"[Flow] otpauth: {setup.OtpauthUri}");

        // Logout per forzare nuovo login con MFA
        await _api.LogoutAsync();

        Log("[Flow] Login per MFA");
        var loginMfa = await _api.LoginAsync(username, password, rememberMe: true);
        if (loginMfa.Error != "mfa_required" || string.IsNullOrWhiteSpace(loginMfa.ChallengeId))
        {
            Log($"[Flow] Login non richiede MFA (error={loginMfa.Error})");
            return;
        }

        // Attendere inserimento TOTP
        if (string.IsNullOrWhiteSpace(txtTotp.Text))
        {
            Log("[Flow] Inserisci il codice TOTP nella textbox e ripremi il bottone");
            return;
        }

        Log("[Flow] Conferma MFA");
        var confirm = await _api.ConfirmMfaAsync(loginMfa.ChallengeId, txtTotp.Text.Trim(), rememberMe: true);
        if (!confirm.Ok)
        {
            Log($"[Flow] Confirm MFA fallita: {confirm.Error}");
            return;
        }

        Log("[Flow] /me");
        var me = await _api.MeAsync();
        if (me is not null && me.Ok)
        {
            Log($"[Flow] /me OK user={me.UserId}");
        }
        else
        {
            Log("[Flow] /me fallito dopo MFA");
        }
    }

    private async Task<T?> PostJson<T>(string path, object payload, string? csrfHeader = null)
    {
        if (_rawHttp == null) throw new InvalidOperationException("HttpClient non inizializzato");

        using var req = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json")
        };
        if (!string.IsNullOrWhiteSpace(csrfHeader))
        {
            req.Headers.Add("X-CSRF-Token", csrfHeader);
        }

        var resp = await _rawHttp.SendAsync(req);
        var content = await resp.Content.ReadAsStringAsync();
        if (!resp.IsSuccessStatusCode)
        {
            Log($"POST {path} -> {(int)resp.StatusCode}\n{content}");
            return default;
        }

        return JsonSerializer.Deserialize<T>(content, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
    }

    private void Log(string message)
    {
        txtLog.AppendText($"[{DateTime.Now:HH:mm:ss}] {message}{Environment.NewLine}");
    }

    private sealed record MfaSetupResponse(bool Ok, string? Secret, string? OtpauthUri);
    private sealed record RegisterResp(string? UserId, string? EmailConfirmToken);
}
