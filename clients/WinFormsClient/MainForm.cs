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
    private const int ButtonWidth = 120;
    private const int QrSize = 160;

    private UrlInputControl _urlControl = null!;
    private TextBox _userBox = null!;
    private TextBox _emailBox = null!;
    private PasswordInputControl _passwordControl = null!;
    private TextBox _totpBox = null!;
    private ActionButtonsControl _actions = null!;
    private Label _stateLabel = null!;
    private Label _userLabel = null!;
    private Label _sessionLabel = null!;
    private Label _expLabel = null!;
    private Label _rememberLabel = null!;
    private Label _badgeLabel = null!;
    private StatusBanner _banner = null!;
    private TextBox _outputBox = null!;
    private ListBox _logBox = null!;
    private Label _busyLabel = null!;
    private SessionCard _sessionCard = null!;
    private DeviceInfoControl _deviceInfo = null!;
    private DeviceAlertControl _deviceAlert = null!;
    private TextBox _challengeBox = null!;
    private Label _mfaStatusLabel = null!;
    private TextBox _confirmTokenBox = null!;
    private PictureBox _qrBox = null!;
    private System.Windows.Forms.Timer _countdownTimer = null!;
    private DateTime? _refreshExpiresUtc;
    private string? _challengeId;
    private string? _otpauthUri;

    private HttpClient _http = null!;
    private HttpClientHandler _handler = null!;
    private CookieContainer _cookies = null!;
    private string? _csrfToken;

    public MainForm()
    {
        _urlControl = new UrlInputControl();
        _userBox = new TextBox { Text = "demo" };
        _emailBox = new TextBox { Text = "demo@example.com" };
        _passwordControl = new PasswordInputControl();
        _totpBox = new TextBox { Text = "", PlaceholderText = "TOTP (se richiesto)" };
        _actions = new ActionButtonsControl();
        _stateLabel = new Label { Text = "Stato: Non autenticato", AutoSize = true };
        _userLabel = new Label { Text = "Utente: -", AutoSize = true };
        _sessionLabel = new Label { Text = "SessionId: -", AutoSize = true };
        _expLabel = new Label { Text = "Scadenza: -", AutoSize = true };
        _rememberLabel = new Label { Text = "Remember: -", AutoSize = true };
        _badgeLabel = new Label { AutoSize = true, Padding = new Padding(6), BackColor = System.Drawing.Color.Firebrick, ForeColor = System.Drawing.Color.White, Text = "Non autenticato" };
        _banner = new StatusBanner();
        _outputBox = new TextBox { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, Height = 180 };
        _logBox = new ListBox { Height = 120 };
        _busyLabel = new Label { Text = "", AutoSize = true, ForeColor = System.Drawing.Color.DarkSlateGray };
        _sessionCard = new SessionCard();
        _deviceInfo = new DeviceInfoControl();
        _deviceAlert = new DeviceAlertControl();
        _challengeBox = new TextBox { ReadOnly = true, PlaceholderText = "Challenge MFA" };
        _mfaStatusLabel = new Label { Text = "MFA: -", AutoSize = true };
        _confirmTokenBox = new TextBox { PlaceholderText = "Token conferma email" };
        _qrBox = new PictureBox { SizeMode = PictureBoxSizeMode.StretchImage, Height = QrSize, Width = QrSize, BorderStyle = BorderStyle.FixedSingle, BackColor = System.Drawing.Color.White };
        _countdownTimer = new System.Windows.Forms.Timer { Interval = 1000 };

        Text = "SecureAuth WinForms Client";
        Width = 1100;
        Height = 800;

        Controls.Clear();
        _banner.Dock = DockStyle.Top;
        Controls.Add(_banner);

        var root = new Panel
        {
            AutoScroll = true,
            Dock = DockStyle.None,
            Size = new System.Drawing.Size(1100, 760),
            Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Bottom
        };
        Controls.Add(root);

        // Colonna sinistra
        _urlControl.Location = new Point(10, 10);
        _urlControl.Size = new Size(500, 32);
        _urlControl.UrlText = "https://localhost:52899";
        root.Controls.Add(_urlControl);

        _userBox.Location = new Point(10, 55);
        _userBox.Size = new Size(300, 23);
        _userBox.Text = "demo";
        root.Controls.Add(_userBox);

        _emailBox.Location = new Point(10, 85);
        _emailBox.Size = new Size(300, 23);
        _emailBox.Text = "demo@example.com";
        root.Controls.Add(_emailBox);

        _passwordControl.Location = new Point(10, 115);
        _passwordControl.Size = new Size(320, 32);
        _passwordControl.PasswordText = "demo";
        root.Controls.Add(_passwordControl);

        _totpBox.Location = new Point(10, 155);
        _totpBox.Size = new Size(200, 23);
        root.Controls.Add(_totpBox);

        _actions.Location = new Point(10, 190);
        _actions.Size = new Size(200, 280);
        root.Controls.Add(_actions);

        _challengeBox.Location = new Point(10, 480);
        _challengeBox.Size = new Size(200, 23);
        root.Controls.Add(_challengeBox);

        _qrBox.Location = new Point(10, 510);
        root.Controls.Add(_qrBox);

        _outputBox.Location = new Point(10, 680);
        _outputBox.Size = new Size(700, 150);
        root.Controls.Add(_outputBox);

        _logBox.Location = new Point(10, 840);
        _logBox.Size = new Size(700, 140);
        root.Controls.Add(_logBox);

        _confirmTokenBox.Location = new Point(10, 990);
        _confirmTokenBox.Size = new Size(300, 23);
        root.Controls.Add(_confirmTokenBox);

        // Colonna destra
        int rightX = 550;
        _badgeLabel.Location = new Point(rightX, 20);
        root.Controls.Add(_badgeLabel);
        _stateLabel.Location = new Point(rightX, 55);
        root.Controls.Add(_stateLabel);
        _userLabel.Location = new Point(rightX, 75);
        root.Controls.Add(_userLabel);
        _sessionLabel.Location = new Point(rightX, 95);
        root.Controls.Add(_sessionLabel);
        _expLabel.Location = new Point(rightX, 115);
        root.Controls.Add(_expLabel);
        _rememberLabel.Location = new Point(rightX, 135);
        root.Controls.Add(_rememberLabel);
        _mfaStatusLabel.Location = new Point(rightX, 155);
        root.Controls.Add(_mfaStatusLabel);

        _sessionCard.Location = new Point(rightX, 190);
        _sessionCard.Size = new Size(320, 140);
        root.Controls.Add(_sessionCard);

        _deviceInfo.Location = new Point(rightX, 340);
        _deviceInfo.Size = new Size(320, 90);
        root.Controls.Add(_deviceInfo);

        _deviceAlert.Location = new Point(rightX, 440);
        _deviceAlert.Size = new Size(320, 60);
        root.Controls.Add(_deviceAlert);

        _busyLabel.Location = new Point(rightX, 510);
        root.Controls.Add(_busyLabel);

        _actions.RegisterClicked += async (_, _) => await RegisterAsync();
        _actions.ConfirmEmailClicked += async (_, _) => await ConfirmEmailAsync();
        _actions.LoginClicked += async (_, _) => await LoginAsync();
        _actions.ConfirmMfaClicked += async (_, _) => await ConfirmMfaAsync();
        _actions.RefreshClicked += async (_, _) => await RefreshAsync();
        _actions.SetupMfaClicked += async (_, _) => await SetupMfaAsync();
        _actions.DisableMfaClicked += async (_, _) => await DisableMfaAsync();
        _actions.MeClicked += async (_, _) => await MeAsync();
        _actions.LogoutClicked += async (_, _) => await LogoutAsync();
        _actions.ShowQrClicked += (_, _) => RenderQr();
        _countdownTimer.Tick += (_, _) => _sessionCard.TickCountdown();
    }

    private Uri BaseUri => new(_urlControl.UrlText.TrimEnd('/'));

    /// <summary>
    /// Esegue registrazione utente con username/password correnti.
    /// </summary>
    private async Task RegisterAsync()
    {
        using var busy = BeginBusy("Registrazione in corso...");
        try
        {
        var payload = new { username = _userBox.Text, password = _passwordControl.PasswordText, email = _emailBox.Text };
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
    /// Esegue login (solo password) e salva eventuale challenge MFA o la sessione.
    /// </summary>
    private async Task LoginAsync()
    {
        using var busy = BeginBusy("Login in corso...");
        try
        {
        var payload = new { username = _userBox.Text, password = _passwordControl.PasswordText, rememberMe = _actions.RememberChecked };
            var response = await _http.PostAsJsonAsync(new Uri(BaseUri, "/login"), payload);
            var body = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                // Gestione MFA required
                try
                {
                    var mfa = JsonSerializer.Deserialize<MfaRequiredResponse>(body, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                    if (mfa?.Error == "mfa_required")
                    {
                        _challengeId = mfa.ChallengeId;
                        _challengeBox.Text = mfa.ChallengeId ?? "";
                        _actions.SetMfaEnabled(!string.IsNullOrWhiteSpace(_challengeId));
                        SetMfaState("MFA richiesta: inserisci TOTP e conferma");
                        Append($"Login richiede MFA: challengeId={mfa.ChallengeId}");
                        LogEvent("Info", "MFA richiesta, procedi con la conferma");
                        return;
                    }
                }
                catch
                {
                    // ignore parse errors, gestisci come errore generico
                }

                Append($"Login fallito: {(int)response.StatusCode} {response.ReasonPhrase}\n{body}");
                LogEvent("Errore", $"Login fallito status={(int)response.StatusCode}");
                return;
            }

            var login = JsonSerializer.Deserialize<LoginResponse>(body, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            _csrfToken = login?.CsrfToken;
            _rememberLabel.Text = $"Remember: {(login?.RememberIssued == true ? "Emesso" : "Non emesso")}";
            _deviceInfo.UpdateDevice(login?.DeviceId, login?.DeviceIssued);
            _deviceAlert.SetStatus(true, "Login/Device OK");
            ClearMfa();
            if (string.IsNullOrWhiteSpace(_csrfToken))
            {
                Append($"Login riuscito ma csrfToken non presente: body={body}");
                LogEvent("Info", "Login OK");
            }
            else
            {
                Append($"Login OK. csrfToken={_csrfToken}");
                LogEvent("Info", "Login OK");
                if (login?.RefreshExpiresAtUtc is not null && DateTime.TryParse(login.RefreshExpiresAtUtc, out var refreshExp))
                {
                    _refreshExpiresUtc = refreshExp.ToUniversalTime();
                }
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
    /// Conclude il login per utenti MFA con il challenge ricevuto.
    /// </summary>
    private async Task ConfirmMfaAsync()
    {
        using var busy = BeginBusy("Conferma MFA in corso...");
        try
        {
            if (string.IsNullOrWhiteSpace(_challengeId))
            {
                Append("Nessun challenge MFA salvato: esegui prima il login.");
                LogEvent("Errore", "Conferma MFA senza challenge");
                return;
            }
            if (string.IsNullOrWhiteSpace(_totpBox.Text))
            {
                Append("Inserire il codice TOTP.");
                LogEvent("Errore", "TOTP mancante");
                return;
            }

            var payload = new { challengeId = _challengeId, totpCode = _totpBox.Text, rememberMe = _actions.RememberChecked };
            var response = await _http.PostAsJsonAsync(new Uri(BaseUri, "/login/confirm-mfa"), payload);
            var body = await response.Content.ReadAsStringAsync();
            Append($"POST /login/confirm-mfa -> {(int)response.StatusCode}\n{body}");
            if (!response.IsSuccessStatusCode)
            {
                LogEvent("Errore", $"Confirm MFA fallita status={(int)response.StatusCode}");
                SetMfaState("MFA fallita: controlla codice/challenge");
                return;
            }

            var confirm = JsonSerializer.Deserialize<MfaConfirmResponse>(body, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            _csrfToken = confirm?.CsrfToken ?? _csrfToken;
            _rememberLabel.Text = $"Remember: {(confirm?.RememberIssued == true ? "Emesso" : "Non emesso")}";
            _deviceInfo.UpdateDevice(confirm?.DeviceId, confirm?.DeviceIssued);
            _deviceAlert.SetStatus(true, "MFA confermata");
            if (confirm?.RefreshExpiresAtUtc is not null && DateTime.TryParse(confirm.RefreshExpiresAtUtc, out var refreshExp))
            {
                _refreshExpiresUtc = refreshExp.ToUniversalTime();
            }
            ClearMfa();
            LogEvent("Info", "MFA confermata, sessione attiva");
            await RefreshSessionInfoAsync();
        }
        catch (Exception ex)
        {
            Append($"Errore conferma MFA: {ex.Message}");
            LogEvent("Errore", $"Conferma MFA eccezione: {ex.Message}");
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
                var reason = response.StatusCode == HttpStatusCode.Unauthorized
                    ? "Refresh negato (token o device mancante/non valido)"
                    : $"Refresh fallito status={(int)response.StatusCode}";
                _deviceAlert.SetStatus(false, reason);
                LogEvent("Errore", reason);
                LogEvent("Errore", $"Refresh fallito status={(int)response.StatusCode}");
                return;
            }
            var login = JsonSerializer.Deserialize<LoginResponse>(body, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            _csrfToken = login?.CsrfToken ?? _csrfToken;
            _rememberLabel.Text = $"Remember: {(login?.RememberIssued == true ? "Emesso" : "Non emesso")}";
            _deviceInfo.UpdateDevice(login?.DeviceId, login?.DeviceIssued);
            _deviceAlert.SetStatus(true, "Refresh/Device OK");
            if (login?.RefreshExpiresAtUtc is not null && DateTime.TryParse(login.RefreshExpiresAtUtc, out var refreshExp))
            {
                _refreshExpiresUtc = refreshExp.ToUniversalTime();
            }
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
                _otpauthUri = setup?.OtpauthUri;
                RenderQr();
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
        _actions.SetEnabled(enabled);
        _actions.SetMfaEnabled(enabled && !string.IsNullOrWhiteSpace(_challengeId));
        _actions.SetQrEnabled(enabled && !string.IsNullOrWhiteSpace(_otpauthUri));
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

    private sealed record LoginResponse(bool Ok, string? CsrfToken, bool? RememberIssued, string? RefreshExpiresAtUtc, bool? DeviceIssued, string? DeviceId);
    private sealed record RegisterResponse(bool Ok, string? UserId, string? EmailConfirmToken, string? EmailConfirmExpiresUtc);
    private sealed record MeResponse(bool Ok, string SessionId, string UserId, string CreatedAtUtc, string ExpiresAtUtc);
    private sealed record MfaSetupResponse(bool Ok, string? Secret, string? OtpauthUri);
    private sealed record MfaRequiredResponse(bool? Ok, string? Error, string? ChallengeId);
    private sealed record MfaConfirmResponse(bool Ok, string? CsrfToken, bool? RememberIssued, string? RefreshExpiresAtUtc, bool? DeviceIssued, string? DeviceId);

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
        _refreshExpiresUtc = null;
        _otpauthUri = null;
        _qrBox.Image = null;
        _actions.SetQrEnabled(false);
        SetState("Non autenticato", null, null, null);
        _deviceInfo.ResetInfo();
        _deviceAlert.ResetStatus();
        ClearMfa();
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
        _sessionCard.UpdateInfo(userId, sessionId, expiresAtUtc, createdAtUtc, _refreshExpiresUtc);

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

    private void ClearMfa()
    {
        _challengeId = null;
        _challengeBox.Text = "";
        _actions.SetMfaEnabled(false);
        SetMfaState("MFA: -");
    }

    private void SetMfaState(string message)
    {
        _mfaStatusLabel.Text = message;
    }

    private void RenderQr()
    {
        if (string.IsNullOrWhiteSpace(_otpauthUri))
        {
            _qrBox.Image = null;
            _actions.SetQrEnabled(false);
            return;
        }

        try
        {
            using var generator = new QRCoder.QRCodeGenerator();
            using var data = generator.CreateQrCode(_otpauthUri, QRCoder.QRCodeGenerator.ECCLevel.Q);
            using var code = new QRCoder.QRCode(data);
            var bmp = code.GetGraphic(20);
            _qrBox.Image = bmp;
            _actions.SetQrEnabled(true);
            Append("QR MFA generato: scansiona con Authenticator");
            LogEvent("Info", "QR MFA generato");
        }
        catch (Exception ex)
        {
            _qrBox.Image = null;
            LogEvent("Errore", $"QR MFA non generato: {ex.Message}");
        }
    }
}
