using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows.Forms;
using WinFormsClient.Controls;

namespace WinFormsClient;

/// <summary>
/// Client WinForms che effettua registrazione, login, me e logout contro l'API usando cookie HttpOnly e CSRF header.
/// </summary>
public sealed class MainForm : Form
{
    private readonly TextBox _urlBox = new() { Text = "https://localhost:52899", Dock = DockStyle.Fill };
    private readonly TextBox _userBox = new() { Text = "demo", Dock = DockStyle.Fill };
    private readonly TextBox _emailBox = new() { Text = "demo@example.com", Dock = DockStyle.Fill };
    private readonly TextBox _passBox = new() { Text = "demo", UseSystemPasswordChar = true, Dock = DockStyle.Fill };
    private readonly TextBox _totpBox = new() { Text = "", Dock = DockStyle.Fill, PlaceholderText = "TOTP (se richiesto)" };
    private readonly Button _registerButton = new() { Text = "Registrati" };
    private readonly Button _confirmEmailButton = new() { Text = "Conferma email" };
    private readonly Button _loginButton = new() { Text = "Login" };
    private readonly Button _setupMfaButton = new() { Text = "Attiva MFA" };
    private readonly Button _disableMfaButton = new() { Text = "Disattiva MFA" };
    private readonly Button _refreshButton = new() { Text = "Refresh" };
    private readonly Button _meButton = new() { Text = "Mostra profilo" };
    private readonly Button _logoutButton = new() { Text = "Logout" };
    private readonly CheckBox _rememberCheck = new() { Text = "Ricordami", AutoSize = true };
    private readonly Label _stateLabel = new() { Text = "Stato: Non autenticato", AutoSize = true };
    private readonly Label _userLabel = new() { Text = "Utente: -", AutoSize = true };
    private readonly Label _sessionLabel = new() { Text = "SessionId: -", AutoSize = true };
    private readonly Label _expLabel = new() { Text = "Scadenza: -", AutoSize = true };
    private readonly Label _rememberLabel = new() { Text = "Remember: -", AutoSize = true };
    private readonly Label _badgeLabel = new() { AutoSize = true, Padding = new Padding(6), BackColor = System.Drawing.Color.Firebrick, ForeColor = System.Drawing.Color.White, Text = "Non autenticato" };
    private readonly StatusBanner _banner = new();
    private readonly TextBox _outputBox = new() { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, Dock = DockStyle.Fill, Height = 180 };
    private readonly ListBox _logBox = new() { Dock = DockStyle.Fill, Height = 120 };
    private readonly Label _busyLabel = new() { Text = "", AutoSize = true, ForeColor = System.Drawing.Color.DarkSlateGray };
    private readonly SessionCard _sessionCard = new();
    private readonly TextBox _confirmTokenBox = new() { Dock = DockStyle.Fill, PlaceholderText = "Token conferma email" };
    private readonly System.Windows.Forms.Timer _countdownTimer = new() { Interval = 1000 };

    private HttpClient _http = null!;
    private HttpClientHandler _handler = null!;
    private CookieContainer _cookies = null!;
    private string? _csrfToken;

    public MainForm()
    {
        Text = "SecureAuth WinForms Client";
        Width = 640;
        Height = 420;

        // Gestore HTTP condiviso con cookie jar; accetta cert dev self-signed.
        ResetHttpClient();

        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = 12,
            Padding = new Padding(10),
            AutoSize = true
        };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

        layout.Controls.Add(new Label { Text = "Base URL:", AutoSize = true }, 0, 0);
        layout.Controls.Add(_urlBox, 1, 0);

        layout.Controls.Add(new Label { Text = "Username:", AutoSize = true }, 0, 1);
        layout.Controls.Add(_userBox, 1, 1);

        layout.Controls.Add(new Label { Text = "Email:", AutoSize = true }, 0, 2);
        layout.Controls.Add(_emailBox, 1, 2);

        layout.Controls.Add(new Label { Text = "Password:", AutoSize = true }, 0, 3);
        layout.Controls.Add(_passBox, 1, 3);

        layout.Controls.Add(new Label { Text = "TOTP (opzionale):", AutoSize = true }, 0, 4);
        layout.Controls.Add(_totpBox, 1, 4);

        var buttonsPanel = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true };
        buttonsPanel.Controls.AddRange(new Control[] { _registerButton, _confirmEmailButton, _loginButton, _rememberCheck, _refreshButton, _setupMfaButton, _disableMfaButton, _meButton, _logoutButton });
        layout.Controls.Add(buttonsPanel, 1, 5);

        var statusPanel = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, FlowDirection = FlowDirection.TopDown };
        statusPanel.Controls.AddRange(new Control[] { _badgeLabel, _stateLabel, _userLabel, _sessionLabel, _expLabel, _rememberLabel });
        layout.Controls.Add(statusPanel, 0, 6);
        layout.SetColumnSpan(statusPanel, 2);

        layout.Controls.Add(_sessionCard, 0, 7);
        layout.SetColumnSpan(_sessionCard, 2);

        layout.Controls.Add(_outputBox, 0, 8);
        layout.SetColumnSpan(_outputBox, 2);

        layout.Controls.Add(_busyLabel, 0, 9);
        layout.SetColumnSpan(_busyLabel, 2);

        layout.Controls.Add(new Label { Text = "Log eventi:", AutoSize = true }, 0, 9);
        layout.Controls.Add(_logBox, 0, 10);
        layout.SetColumnSpan(_logBox, 2);

        layout.Controls.Add(new Label { Text = "Token conferma email:", AutoSize = true }, 0, 11);
        layout.Controls.Add(_confirmTokenBox, 1, 11);

        // Aggiungi prima il layout (fill), poi il banner top per riservare spazio.
        Controls.Add(layout);
        Controls.Add(_banner);

        _registerButton.Click += async (_, _) => await RegisterAsync();
        _confirmEmailButton.Click += async (_, _) => await ConfirmEmailAsync();
        _loginButton.Click += async (_, _) => await LoginAsync();
        _refreshButton.Click += async (_, _) => await RefreshAsync();
        _setupMfaButton.Click += async (_, _) => await SetupMfaAsync();
        _disableMfaButton.Click += async (_, _) => await DisableMfaAsync();
        _meButton.Click += async (_, _) => await MeAsync();
        _logoutButton.Click += async (_, _) => await LogoutAsync();
        _countdownTimer.Tick += (_, _) => _sessionCard.TickCountdown();
    }

    private Uri BaseUri => new(_urlBox.Text.TrimEnd('/'));

    /// <summary>
    /// Esegue registrazione utente con username/password correnti.
    /// </summary>
    private async Task RegisterAsync()
    {
        using var busy = BeginBusy("Registrazione in corso...");
        try
        {
            var payload = new { username = _userBox.Text, password = _passBox.Text, email = _emailBox.Text };
            var response = await _http.PostAsJsonAsync(new Uri(BaseUri, "/register"), payload);
            var body = await response.Content.ReadAsStringAsync();

            if (response.StatusCode == HttpStatusCode.Created)
            {
                var reg = JsonSerializer.Deserialize<RegisterResponse>(body, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                _confirmTokenBox.Text = reg?.EmailConfirmToken ?? "";
                Append($"Registrazione OK. userId={reg?.UserId} token={reg?.EmailConfirmToken}");
                LogEvent("Info", $"Registrazione utente {reg?.UserId} token conferma impostato");
                SetState("Non autenticato", null, null, null);
                return;
            }

            Append($"Registrazione fallita: {(int)response.StatusCode} {response.ReasonPhrase}\n{body}");
            LogEvent("Errore", $"Registrazione fallita status={(int)response.StatusCode}");
        }
        catch (Exception ex)
        {
            Append($"Errore registrazione: {ex.Message}");
            LogEvent("Errore", $"Registrazione eccezione: {ex.Message}");
        }
    }

    /// <summary>
    /// Esegue login demo/demo e salva il token CSRF per le chiamate di logout.
    /// </summary>
    private async Task LoginAsync()
    {
        using var busy = BeginBusy("Login in corso...");
        try
        {
            var payload = new { username = _userBox.Text, password = _passBox.Text, totpCode = _totpBox.Text, rememberMe = _rememberCheck.Checked };
            var response = await _http.PostAsJsonAsync(new Uri(BaseUri, "/login"), payload);
            var body = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                Append($"Login fallito: {(int)response.StatusCode} {response.ReasonPhrase}\n{body}");
                LogEvent("Errore", $"Login fallito status={(int)response.StatusCode}");
                return;
            }

            var login = JsonSerializer.Deserialize<LoginResponse>(body, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            _csrfToken = login?.CsrfToken;
            _rememberLabel.Text = $"Remember: {(login?.RememberIssued == true ? "Emesso" : "Non emesso")}";
            if (string.IsNullOrWhiteSpace(_csrfToken))
            {
                Append($"Login riuscito ma csrfToken non presente: body={body}");
                LogEvent("Info", "Login OK");
            }
            else
            {
                Append($"Login OK. csrfToken={_csrfToken}");
                LogEvent("Info", "Login OK");
                await RefreshSessionInfoAsync();
            }
        }
        catch (Exception ex)
        {
            Append($"Errore login: {ex.Message}");
            LogEvent("Errore", $"Login eccezione: {ex.Message}");
        }
    }

    /// <summary>
    /// Chiede un nuovo access/refresh chiamando /refresh.
    /// </summary>
    private async Task RefreshAsync()
    {
        using var busy = BeginBusy("Refresh in corso...");
        try
        {
            var response = await _http.PostAsync(new Uri(BaseUri, "/refresh"), content: null);
            var body = await response.Content.ReadAsStringAsync();
            Append($"POST /refresh -> {(int)response.StatusCode}\n{body}");
            if (!response.IsSuccessStatusCode)
            {
                LogEvent("Errore", $"Refresh fallito status={(int)response.StatusCode}");
                return;
            }
            var login = JsonSerializer.Deserialize<LoginResponse>(body, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            _csrfToken = login?.CsrfToken ?? _csrfToken;
            _rememberLabel.Text = $"Remember: {(login?.RememberIssued == true ? "Emesso" : "Non emesso")}";
            LogEvent("Info", "Refresh OK");
            await RefreshSessionInfoAsync();
        }
        catch (Exception ex)
        {
            Append($"Errore refresh: {ex.Message}");
            LogEvent("Errore", $"Refresh eccezione: {ex.Message}");
        }
    }

    /// <summary>
    /// Conferma email usando il token (solo dev).
    /// </summary>
    private async Task ConfirmEmailAsync()
    {
        using var busy = BeginBusy("Conferma email in corso...");
        try
        {
            var token = _confirmTokenBox.Text;
            if (string.IsNullOrWhiteSpace(token))
            {
                Append("Token conferma email mancante.");
                LogEvent("Errore", "Token conferma email mancante");
                return;
            }

            var payload = new { token };
            var response = await _http.PostAsJsonAsync(new Uri(BaseUri, "/confirm-email"), payload);
            var body = await response.Content.ReadAsStringAsync();
            Append($"POST /confirm-email -> {(int)response.StatusCode}\n{body}");

            if (response.IsSuccessStatusCode)
            {
                LogEvent("Info", "Email confermata");
            }
            else
            {
                LogEvent("Errore", $"Conferma email fallita status={(int)response.StatusCode}");
            }
        }
        catch (Exception ex)
        {
            Append($"Errore conferma email: {ex.Message}");
            LogEvent("Errore", $"Conferma email eccezione: {ex.Message}");
        }
    }

    /// <summary>
    /// Chiama l'endpoint /me usando il cookie salvato nel CookieContainer.
    /// </summary>
    private async Task MeAsync()
    {
        using var busy = BeginBusy("Richiesta /me in corso...");
        try
        {
            await RefreshSessionInfoAsync();
        }
        catch (Exception ex)
        {
            Append($"Errore /me: {ex.Message}");
            LogEvent("Errore", $"/me eccezione: {ex.Message}");
        }
    }

    /// <summary>
    /// Chiama /mfa/setup e mostra il segreto per l'app TOTP.
    /// </summary>
    private async Task SetupMfaAsync()
    {
        using var busy = BeginBusy("Setup MFA in corso...");
        try
        {
            if (string.IsNullOrWhiteSpace(_csrfToken))
            {
                Append("CSRF token non disponibile: effettua il login prima di attivare MFA.");
                LogEvent("Errore", "Setup MFA senza login");
                return;
            }

            var req = new HttpRequestMessage(HttpMethod.Post, new Uri(BaseUri, "/mfa/setup"));
            req.Headers.Add("X-CSRF-Token", _csrfToken);
            var resp = await _http.SendAsync(req);
            var body = await resp.Content.ReadAsStringAsync();
            Append($"POST /mfa/setup -> {(int)resp.StatusCode}\n{body}");

            if (resp.IsSuccessStatusCode)
            {
                var setup = JsonSerializer.Deserialize<MfaSetupResponse>(body, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                LogEvent("Info", $"MFA attivata secret={setup?.Secret}");
            }
            else
            {
                LogEvent("Errore", $"Setup MFA fallito status={(int)resp.StatusCode}");
            }
        }
        catch (Exception ex)
        {
            Append($"Errore setup MFA: {ex.Message}");
            LogEvent("Errore", $"Setup MFA eccezione: {ex.Message}");
        }
    }

    /// <summary>
    /// Disattiva MFA per l'utente corrente.
    /// </summary>
    private async Task DisableMfaAsync()
    {
        using var busy = BeginBusy("Disattivazione MFA in corso...");
        try
        {
            if (string.IsNullOrWhiteSpace(_csrfToken))
            {
                Append("CSRF token non disponibile: effettua il login prima di disattivare MFA.");
                LogEvent("Errore", "Disattiva MFA senza login");
                return;
            }

            var req = new HttpRequestMessage(HttpMethod.Post, new Uri(BaseUri, "/mfa/disable"));
            req.Headers.Add("X-CSRF-Token", _csrfToken);
            var resp = await _http.SendAsync(req);
            var body = await resp.Content.ReadAsStringAsync();
            Append($"POST /mfa/disable -> {(int)resp.StatusCode}\n{body}");

            if (resp.IsSuccessStatusCode)
            {
                LogEvent("Info", "MFA disattivata");
            }
            else
            {
                LogEvent("Errore", $"Disattiva MFA fallito status={(int)resp.StatusCode}");
            }
        }
        catch (Exception ex)
        {
            Append($"Errore disattiva MFA: {ex.Message}");
            LogEvent("Errore", $"Disattiva MFA eccezione: {ex.Message}");
        }
    }

    /// <summary>
    /// Esegue /logout inviando il CSRF e resetta il client se la revoca va a buon fine.
    /// </summary>
    private async Task LogoutAsync()
    {
        using var busy = BeginBusy("Logout in corso...");
        try
        {
            if (string.IsNullOrWhiteSpace(_csrfToken))
            {
                Append("CSRF token non disponibile: effettua il login prima del logout.");
                LogEvent("Errore", "Logout senza CSRF");
                return;
            }

            var req = new HttpRequestMessage(HttpMethod.Post, new Uri(BaseUri, "/logout"));
            req.Headers.Add("X-CSRF-Token", _csrfToken);

            var response = await _http.SendAsync(req);
            var body = await response.Content.ReadAsStringAsync();
            Append($"POST /logout -> {(int)response.StatusCode}\n{body}");

            if (response.IsSuccessStatusCode)
            {
                _csrfToken = null;
                ResetHttpClient(); // pulisci cookie jar per evitare riuso client-side
                SetState("Non autenticato", null, null, null);
                LogEvent("Info", "Logout OK");
            }
            else
            {
                LogEvent("Errore", $"Logout fallito status={(int)response.StatusCode}");
            }
        }
        catch (Exception ex)
        {
            Append($"Errore logout: {ex.Message}");
            LogEvent("Errore", $"Logout eccezione: {ex.Message}");
        }
    }

    private void Append(string message)
    {
        _outputBox.AppendText($"[{DateTime.Now:T}] {message}{Environment.NewLine}");
    }

    private void LogEvent(string level, string message)
    {
        _logBox.Items.Insert(0, $"[{DateTime.Now:T}] {level}: {message}");
        if (_logBox.Items.Count > 200)
        {
            _logBox.Items.RemoveAt(_logBox.Items.Count - 1);
        }
    }

    private IDisposable BeginBusy(string message)
    {
        _busyLabel.Text = message;
        SetButtonsEnabled(false);
        return new BusyScope(() =>
        {
            _busyLabel.Text = "";
            SetButtonsEnabled(true);
        });
    }

    private void SetButtonsEnabled(bool enabled)
    {
        _registerButton.Enabled = enabled;
        _confirmEmailButton.Enabled = enabled;
        _loginButton.Enabled = enabled;
        _refreshButton.Enabled = enabled;
        _meButton.Enabled = enabled;
        _logoutButton.Enabled = enabled;
    }

    private sealed class BusyScope : IDisposable
    {
        private readonly Action _onDispose;
        private bool _disposed;

        public BusyScope(Action onDispose)
        {
            _onDispose = onDispose;
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            _onDispose();
        }
    }

    private sealed record LoginResponse(bool Ok, string? CsrfToken, bool? RememberIssued);
    private sealed record RegisterResponse(bool Ok, string? UserId, string? EmailConfirmToken, string? EmailConfirmExpiresUtc);
    private sealed record MeResponse(bool Ok, string SessionId, string UserId, string CreatedAtUtc, string ExpiresAtUtc);
    private sealed record MfaSetupResponse(bool Ok, string? Secret, string? OtpauthUri);

    private void ResetHttpClient()
    {
        _cookies = new CookieContainer();
        _handler = new HttpClientHandler
        {
            CookieContainer = _cookies,
            UseCookies = true,
            ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
        };
        _http = new HttpClient(_handler);
        SetState("Non autenticato", null, null, null);
        _countdownTimer.Stop();
    }

    private async Task RefreshSessionInfoAsync()
    {
        var response = await _http.GetAsync(new Uri(BaseUri, "/me"));
        var body = await response.Content.ReadAsStringAsync();
        if (response.StatusCode == HttpStatusCode.OK)
        {
            var me = JsonSerializer.Deserialize<MeResponse>(body, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            if (me is not null)
            {
                Append($"GET /me -> {(int)response.StatusCode}\n{body}");
                SetState("Autenticato", me.UserId, me.SessionId, me.ExpiresAtUtc, createdAtUtc: me.CreatedAtUtc);
                return;
            }
        }

        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            Append($"GET /me -> 401 (sessione scaduta o revocata)\n{body}");
            SetState("Sessione scaduta o revocata", null, null, null);
            return;
        }

        Append($"GET /me -> {(int)response.StatusCode}\n{body}");
    }

    private void SetState(string state, string? userId, string? sessionId, string? expiresAtUtc, string? createdAtUtc = null)
    {
        _stateLabel.Text = $"Stato: {state}";
        _userLabel.Text = $"Utente: {(string.IsNullOrWhiteSpace(userId) ? "-" : userId)}";
        _sessionLabel.Text = $"SessionId: {(string.IsNullOrWhiteSpace(sessionId) ? "-" : sessionId)}";
        _expLabel.Text = $"Scadenza: {(string.IsNullOrWhiteSpace(expiresAtUtc) ? "-" : expiresAtUtc)}";
        _sessionCard.UpdateInfo(userId, sessionId, expiresAtUtc, createdAtUtc);

        switch (state.ToLowerInvariant())
        {
            case "autenticato":
                _badgeLabel.Text = "Autenticato";
                _badgeLabel.BackColor = System.Drawing.Color.SeaGreen;
                _banner.UpdateState(state, userId);
                _countdownTimer.Start();
                break;
            case "sessione scaduta o revocata":
                _badgeLabel.Text = "Sessione scaduta/revocata";
                _badgeLabel.BackColor = System.Drawing.Color.Peru;
                _banner.UpdateState(state, userId);
                _countdownTimer.Stop();
                break;
            default:
                _badgeLabel.Text = "Non autenticato";
                _badgeLabel.BackColor = System.Drawing.Color.Firebrick;
                _banner.UpdateState(state, userId);
                _countdownTimer.Stop();
                break;
        }
    }
}
