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
    private string? _pendingUsername;
    private string? _pendingPassword;
    private string? _pendingChallengeId;
    private string? _pendingOtpauth;

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

        // Se esiste già una challenge pendente, prova solo a confermare MFA
        if (!string.IsNullOrWhiteSpace(_pendingChallengeId))
        {
            await ConfirmPendingMfaAsync();
            return;
        }

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
            _pendingUsername = username;
            _pendingPassword = password;
            _pendingChallengeId = loginMfa.ChallengeId;
            _pendingOtpauth = setup.OtpauthUri;
            Log("[Flow] Inserisci il codice TOTP nella textbox e ripremi il bottone per confermare la MFA");
            return;
        }

        Log("[Flow] Conferma MFA");
        await ConfirmAndFetchMeAsync(loginMfa.ChallengeId, txtTotp.Text.Trim());
        ClearPending();
    }

    private async Task ConfirmPendingMfaAsync()
    {
        if (_api == null || string.IsNullOrWhiteSpace(_pendingUsername) || string.IsNullOrWhiteSpace(_pendingPassword))
        {
            Log("[Flow] Stato pendente mancante, riavviare il flow.");
            ClearPending();
            return;
        }

        if (string.IsNullOrWhiteSpace(txtTotp.Text))
        {
            Log("[Flow] Inserisci il codice TOTP e ripremi il bottone");
            return;
        }

        // se la challenge è scaduta, genera una nuova challenge rifacendo login
        var challengeId = _pendingChallengeId;
        if (string.IsNullOrWhiteSpace(challengeId))
        {
            var relog = await _api.LoginAsync(_pendingUsername, _pendingPassword, rememberMe: true);
            if (relog.Error != "mfa_required" || string.IsNullOrWhiteSpace(relog.ChallengeId))
            {
                Log($"[Flow] Re-login non ha prodotto challenge (error={relog.Error})");
                return;
            }
            challengeId = relog.ChallengeId;
            _pendingChallengeId = challengeId;
            Log("[Flow] Nuova challenge MFA generata dopo re-login");
        }

        await ConfirmAndFetchMeAsync(challengeId, txtTotp.Text.Trim());
        ClearPending();
    }

    private async Task ConfirmAndFetchMeAsync(string challengeId, string totp)
    {
        if (_api == null) return;

        var confirm = await _api.ConfirmMfaAsync(challengeId, totp, rememberMe: true);
        if (!confirm.Ok)
        {
            Log($"[Flow] Confirm MFA fallita: {confirm.Error ?? "unknown"}");
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

    private void ClearPending()
    {
        _pendingUsername = null;
        _pendingPassword = null;
        _pendingChallengeId = null;
        _pendingOtpauth = null;
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
