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
    private string? _currentBaseUrl;

    // Stato per il flow completo o step-by-step
    private string? _username;
    private string? _password;
    private string? _email;
    private string? _confirmToken;
    private string? _csrfToken;
    private string? _challengeId;
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
        var baseUrl = txtBaseUrl.Text.Trim();
        if (_api != null && string.Equals(_currentBaseUrl, baseUrl, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        _currentBaseUrl = baseUrl;
        _api?.Dispose();
        _rawHttp?.Dispose();

        _handler = new HttpClientHandler
        {
            CookieContainer = new System.Net.CookieContainer(),
            UseCookies = true,
            AutomaticDecompression = System.Net.DecompressionMethods.GZip | System.Net.DecompressionMethods.Deflate,
            ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
        };

        _api = new SecureAuthApiClient(new SecureAuthClientOptions
        {
            BaseUrl = baseUrl,
            UserAgent = "WinFORM_AUTH_Client/1.0"
        }, _handler);

        _rawHttp = new HttpClient(_handler, disposeHandler: false)
        {
            BaseAddress = new Uri(baseUrl)
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

        var (username, password, email) = GenerateCredentials();

        // 1) Registrazione + token conferma
        var confirmToken = await RegisterUserAsync(username, password, email);
        if (string.IsNullOrWhiteSpace(confirmToken))
        {
            Log("[Flow] Token conferma mancante, stop");
            return;
        }

        // 2) Conferma email
        await ConfirmEmailAsync(confirmToken);

        // 3) Login password per ottenere CSRF e refresh-CSRF
        var login = await LoginPasswordAsync(username, password);
        if (!login.Ok && login.Error != "mfa_required")
        {
            Log($"[Flow] Login fallito: {login.Error}");
            return;
        }

        // 4) Setup MFA con CSRF
        var setup = await SetupMfaAsync(login.CsrfToken);
        if (setup is null || string.IsNullOrWhiteSpace(setup.Secret))
        {
            Log("[Flow] Setup MFA senza secret, stop");
            return;
        }

        txtOtpauth.Text = setup.OtpauthUri ?? "";
        Log($"[Flow] otpauth: {setup.OtpauthUri}");

        // 5) Logout e nuovo login per ottenere challenge MFA
        await _api.LogoutAsync();
        var loginMfa = await LoginForMfaAsync(username, password);
        if (loginMfa.Error != "mfa_required" || string.IsNullOrWhiteSpace(loginMfa.ChallengeId))
        {
            Log($"[Flow] Login non richiede MFA (error={loginMfa.Error})");
            return;
        }

        // 6) Attesa codice TOTP, salva stato per click successivo
        if (string.IsNullOrWhiteSpace(txtTotp.Text))
        {
            _pendingUsername = username;
            _pendingPassword = password;
            _pendingChallengeId = loginMfa.ChallengeId;
            _pendingOtpauth = setup.OtpauthUri;
            Log("[Flow] Inserisci il codice TOTP nella textbox e ripremi il bottone per confermare la MFA");
            return;
        }

        // 7) Conferma MFA e verifica /me
        Log("[Flow] Conferma MFA");
        await ConfirmAndFetchMeAsync(loginMfa.ChallengeId, txtTotp.Text.Trim());
        ClearPending();
    }

    private async void btnRegister_Click(object sender, EventArgs e)
    {
        try
        {
            EnsureClient();
            (_username, _password, _email) = GenerateCredentials();
            _confirmToken = await RegisterUserAsync(_username, _password, _email);
            if (string.IsNullOrWhiteSpace(_confirmToken))
            {
                Log("[Step] Registrazione ok ma token conferma mancante");
            }
        }
        catch (Exception ex)
        {
            Log($"Errore: {ex.Message}");
        }
    }

    private async void btnConfirmEmail_Click(object sender, EventArgs e)
    {
        try
        {
            EnsureClient();
            if (string.IsNullOrWhiteSpace(_confirmToken))
            {
                Log("[Step] Nessun token di conferma disponibile");
                return;
            }
            await ConfirmEmailAsync(_confirmToken);
        }
        catch (Exception ex)
        {
            Log($"Errore: {ex.Message}");
        }
    }

    private async void btnLoginPwd_Click(object sender, EventArgs e)
    {
        try
        {
            EnsureClient();
            if (string.IsNullOrWhiteSpace(_username) || string.IsNullOrWhiteSpace(_password))
            {
                Log("[Step] Mancano credenziali, registra prima l'utente");
                return;
            }
            var login = await LoginPasswordAsync(_username, _password);
            _csrfToken = login.CsrfToken;
            Log(login.Ok || login.Error == "mfa_required"
                ? "[Step] Login password eseguito"
                : $"[Step] Login fallito: {login.Error}");
        }
        catch (Exception ex)
        {
            Log($"Errore: {ex.Message}");
        }
    }

    private async void btnSetupMfa_Click(object sender, EventArgs e)
    {
        try
        {
            EnsureClient();
            var setup = await SetupMfaAsync(_csrfToken);
            if (setup is null || string.IsNullOrWhiteSpace(setup.Secret))
            {
                Log("[Step] Setup MFA senza secret, fermo");
                return;
            }
            txtOtpauth.Text = setup.OtpauthUri ?? "";
            Log($"[Step] otpauth: {setup.OtpauthUri}");
        }
        catch (Exception ex)
        {
            Log($"Errore: {ex.Message}");
        }
    }

    private async void btnLogout_Click(object sender, EventArgs e)
    {
        try
        {
            EnsureClient();
            if (_api == null) return;
            var res = await _api.LogoutAsync();
            Log(res.Ok ? "[Step] Logout OK" : $"[Step] Logout errore: {res.Error}");
        }
        catch (Exception ex)
        {
            Log($"Errore: {ex.Message}");
        }
    }

    private async void btnLoginMfa_Click(object sender, EventArgs e)
    {
        try
        {
            EnsureClient();
            if (string.IsNullOrWhiteSpace(_username) || string.IsNullOrWhiteSpace(_password))
            {
                Log("[Step] Mancano credenziali, registra prima l'utente");
                return;
            }
            var loginMfa = await LoginForMfaAsync(_username, _password);
            if (loginMfa.Error != "mfa_required" || string.IsNullOrWhiteSpace(loginMfa.ChallengeId))
            {
                Log($"[Step] Login non richiede MFA (error={loginMfa.Error})");
                return;
            }
            _challengeId = loginMfa.ChallengeId;
            Log($"[Step] Challenge MFA: {_challengeId}. Inserisci TOTP e premi Conferma MFA.");
        }
        catch (Exception ex)
        {
            Log($"Errore: {ex.Message}");
        }
    }

    private async void btnConfirmMfa_Click(object sender, EventArgs e)
    {
        try
        {
            EnsureClient();
            if (string.IsNullOrWhiteSpace(txtTotp.Text))
            {
                Log("[Step] Inserisci il codice TOTP");
                return;
            }

            var challenge = _challengeId;
            if (string.IsNullOrWhiteSpace(challenge) && !string.IsNullOrWhiteSpace(_username) && !string.IsNullOrWhiteSpace(_password))
            {
                var relog = await LoginForMfaAsync(_username, _password);
                if (relog.Error == "mfa_required" && !string.IsNullOrWhiteSpace(relog.ChallengeId))
                {
                    challenge = relog.ChallengeId;
                    _challengeId = challenge;
                    Log("[Step] Nuova challenge MFA generata");
                }
            }

            if (string.IsNullOrWhiteSpace(challenge))
            {
                Log("[Step] Nessuna challenge MFA disponibile");
                return;
            }

            await ConfirmAndFetchMeAsync(challenge, txtTotp.Text.Trim());
        }
        catch (Exception ex)
        {
            Log($"Errore: {ex.Message}");
        }
    }

    private async void btnMe_Click(object sender, EventArgs e)
    {
        try
        {
            EnsureClient();
            var me = await _api?.MeAsync()!;
            if (me is not null && me.Ok)
            {
                Log($"[Step] /me OK user={me.UserId}");
            }
            else
            {
                Log("[Step] /me fallito o non autenticato");
            }
        }
        catch (Exception ex)
        {
            Log($"Errore: {ex.Message}");
        }
    }

    /// <summary>
    /// Genera credenziali random per un utente di prova.
    /// </summary>
    private static (string username, string password, string email) GenerateCredentials()
    {
        // 1) Genera credenziali casuali per un nuovo utente di prova
        var username = $"flow-{Guid.NewGuid():N}".Substring(0, 16);
        var password = "FlowUser123!";
        var email = $"{username}@example.com";

        return (username, password, email);
    }

    /// <summary>
    /// Registra un nuovo utente e restituisce il token di conferma email.
    /// </summary>
    private async Task<string?> RegisterUserAsync(string username, string password, string email)
    {
        Log($"[Flow] Register {username}");
        var reg = await PostJson<RegisterResp>("/register", new { username, password, email });
        var confirmToken = reg?.EmailConfirmToken;
        Log($"[Flow] Confirm token: {confirmToken}");
        return confirmToken;
    }

    /// <summary>
    /// Chiama /confirm-email con il token fornito.
    /// </summary>
    private async Task ConfirmEmailAsync(string confirmToken)
    {
        Log("[Flow] Confirm email");
        await PostJson<object>("/confirm-email", new { token = confirmToken });
    }

    /// <summary>
    /// Login password per ottenere CSRF/refresh-CSRF.
    /// </summary>
    private async Task<LoginResult> LoginPasswordAsync(string username, string password)
    {
        Log("[Flow] Login password");
        return await _api!.LoginAsync(username, password, rememberMe: true);
    }

    /// <summary>
    /// Setup MFA usando il CSRF ottenuto dal login.
    /// </summary>
    private async Task<MfaSetupResponse?> SetupMfaAsync(string? csrf)
    {
        Log("[Flow] Setup MFA");
        if (string.IsNullOrWhiteSpace(csrf))
        {
            Log("[Flow] CSRF mancante dopo login, stop");
            return null;
        }

        return await PostJson<MfaSetupResponse>("/mfa/setup", new { }, csrfHeader: csrf);
    }

    /// <summary>
    /// Login che deve produrre una challenge MFA.
    /// </summary>
    private async Task<LoginResult> LoginForMfaAsync(string username, string password)
    {
        Log("[Flow] Login per MFA");
        return await _api!.LoginAsync(username, password, rememberMe: true);
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
