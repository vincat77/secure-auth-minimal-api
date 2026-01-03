using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows.Forms;
using WinFormsClient.Controls;

namespace WinFormsClient;

/// <summary>
/// Client WinForms che effettua registrazione, login, me e logout contro l'API usando cookie HttpOnly e CSRF header.
/// </summary>
public sealed partial class MainForm : Form
{
  private DateTime? _refreshExpiresUtc;
  private string? _challengeId;
  private string? _otpauthUri;

  private HttpClient _http = null!;
  private HttpClientHandler _handler = null!;
  private CookieContainer _cookies = null!;
  private string? _csrfToken;
  private string _rememberText = "-";
  private bool _isAuthenticated;

  public MainForm()
  {
    InitializeComponent();

    EnsureHttpClient();
    _actions.RegisterClicked += async (_, _) => await RegisterAsync();
    _actions.ConfirmEmailClicked += async (_, _) => await ConfirmEmailAsync();
    _actions.LoginClicked += async (_, _) => await LoginAsync();
    _actions.ConfirmMfaClicked += async (_, _) => await ConfirmMfaAsync();
    _actions.RefreshClicked += async (_, _) => await RefreshAsync();
    _actions.SetupMfaClicked += async (_, _) => await SetupMfaAsync();
    _actions.DisableMfaClicked += async (_, _) => await DisableMfaAsync();
    _actions.MeClicked += async (_, _) => await MeAsync();
    _actions.ChangePasswordClicked += async (_, _) => await ChangePasswordAsync();
    _actions.LogoutClicked += async (_, _) => await LogoutAsync();
    _actions.ShowQrClicked += (_, _) => RenderQr();
    _actions.ShowCookiesClicked += (_, _) => DumpCookies();
    _mfaPanel.ConfirmMfaClicked += async (_, _) => await ConfirmMfaAsync();
    _mfaPanel.SetupMfaClicked += async (_, _) => await SetupMfaAsync();
    _mfaPanel.DisableMfaClicked += async (_, _) => await DisableMfaAsync();
    _mfaPanel.ShowQrClicked += (_, _) => RenderQr();
    _countdownTimer.Tick += (_, _) => _sessionCard.TickCountdown();
    ApplyChangePasswordEnabled(false);
  }

  private Uri BaseUri => new(_urlControl.ValueText.TrimEnd('/'));

  /// <summary>
  /// Esegue registrazione utente con username/password correnti.
  /// </summary>
  private async Task RegisterAsync()
  {
    EnsureHttpClient();
    using var busy = BeginBusy("Registrazione in corso...");
    try
    {
      var payload = new
      {
        username = _userInput.ValueText,
        password = _passwordControl.ValueText,
        email = _emailInput.ValueText,
        name = _nameInput.ValueText,
        givenName = _givenNameInput.ValueText,
        familyName = _familyNameInput.ValueText,
        picture = _pictureInput.ValueText
      };
      var response = await _http.PostAsJsonAsync(new Uri(BaseUri, "/register"), payload);
      var body = await response.Content.ReadAsStringAsync();

      if (response.StatusCode == HttpStatusCode.Created)
      {
        var reg = JsonSerializer.Deserialize<RegisterResponse>(body, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        _confirmTokenInput.ValueText = reg?.EmailConfirmToken ?? "";
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
    EnsureHttpClient();
    using var busy = BeginBusy("Login in corso...");
    try
    {
      var payload = new { username = _userInput.ValueText, password = _passwordControl.ValueText, rememberMe = _actions.RememberChecked };
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
            _mfaPanel.ChallengeId = mfa.ChallengeId ?? "";
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
      _rememberText = login?.RememberIssued == true ? "Emesso" : "Non emesso";
      _idTokenViewer.SetToken(login?.IdToken);
#if DEBUG
      if (!string.IsNullOrWhiteSpace(login?.IdToken))
      {
        Append($"id_token: {login.IdToken}");
        LogEvent("Info", "id_token ricevuto (dev)");
      }
#endif
      await LoadProfileImageAsync(login?.IdToken);
      _statusInfo.SetStatus("Autenticato", login?.DeviceId, login?.DeviceId, null, _rememberText, System.Drawing.Color.SeaGreen, "Autenticato");
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
    EnsureHttpClient();
    using var busy = BeginBusy("Conferma MFA in corso...");
    try
    {
      if (string.IsNullOrWhiteSpace(_challengeId))
      {
        Append("Nessun challenge MFA salvato: esegui prima il login.");
        LogEvent("Errore", "Conferma MFA senza challenge");
        return;
      }
      if (string.IsNullOrWhiteSpace(_mfaPanel.TotpCode))
      {
        Append("Inserire il codice TOTP.");
        LogEvent("Errore", "TOTP mancante");
        return;
      }

      var payload = new { challengeId = _challengeId, totpCode = _mfaPanel.TotpCode, rememberMe = _actions.RememberChecked };
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
      _rememberText = confirm?.RememberIssued == true ? "Emesso" : "Non emesso";
      _deviceInfo.UpdateDevice(confirm?.DeviceId, confirm?.DeviceIssued);
      _deviceAlert.SetStatus(true, "MFA confermata");
      _idTokenViewer.SetToken(confirm?.IdToken);
#if DEBUG
      if (!string.IsNullOrWhiteSpace(confirm?.IdToken))
      {
        Append($"id_token: {confirm.IdToken}");
        LogEvent("Info", "id_token ricevuto (dev)");
      }
#endif
      await LoadProfileImageAsync(confirm?.IdToken);
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
    EnsureHttpClient();
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
      _rememberText = login?.RememberIssued == true ? "Emesso" : "Non emesso";
      // /refresh non restituisce id_token; manteniamo l'ultimo ricevuto
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
    EnsureHttpClient();
    using var busy = BeginBusy("Conferma email in corso...");
    try
    {
      var token = _confirmTokenInput.ValueText;
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
    EnsureHttpClient();
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
  /// Cambia la password dell'utente loggato e ruota la sessione.
  /// </summary>
  private async Task ChangePasswordAsync()
  {
    EnsureHttpClient();
    using var busy = BeginBusy("Cambio password in corso...");
    try
    {
      if (string.IsNullOrWhiteSpace(_csrfToken))
      {
        Append("CSRF token non disponibile: effettua il login prima di cambiare password.");
        LogEvent("Errore", "Cambio password senza CSRF");
        return;
      }

      var payload = new
      {
        currentPassword = _currentPasswordInput.ValueText,
        newPassword = _newPasswordInput.ValueText,
        confirmPassword = _confirmPasswordInput.ValueText
      };

      var req = new HttpRequestMessage(HttpMethod.Post, new Uri(BaseUri, "/me/password"))
      {
        Content = JsonContent.Create(payload)
      };
      req.Headers.Add("X-CSRF-Token", _csrfToken);

      var resp = await _http.SendAsync(req);
      var body = await resp.Content.ReadAsStringAsync();
      Append($"POST /me/password -> {(int)resp.StatusCode}\n{body}");

      if (!resp.IsSuccessStatusCode)
      {
        try
        {
          var error = JsonSerializer.Deserialize<ChangePasswordResponse>(body, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
          var extra = error?.Errors is { } errs && errs.Any() ? $" ({string.Join(",", errs)})" : "";
          LogEvent("Errore", $"Cambio password fallito: {error?.Error}{extra}");
        }
        catch
        {
          LogEvent("Errore", $"Cambio password fallito status={(int)resp.StatusCode}");
        }
        return;
      }

      var result = JsonSerializer.Deserialize<ChangePasswordResponse>(body, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
      _csrfToken = result?.CsrfToken ?? _csrfToken;
      ResetChangePasswordForm();
      LogEvent("Info", "Password cambiata e sessione ruotata");
      await RefreshSessionInfoAsync();
    }
    catch (Exception ex)
    {
      Append($"Errore cambio password: {ex.Message}");
      LogEvent("Errore", $"Cambio password eccezione: {ex.Message}");
    }
  }

  /// <summary>
  /// Chiama /mfa/setup e mostra il segreto per l'app TOTP.
  /// </summary>
  private async Task SetupMfaAsync()
  {
    EnsureHttpClient();
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
    EnsureHttpClient();
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
        _idTokenViewer.SetToken(null);
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
    _logPanel.AppendOutput($"[{DateTime.Now:T}] {message}");
  }

  private void LogEvent(string level, string message)
  {
    _logPanel.AddLog($"[{DateTime.Now:T}] {level}: {message}", maxItems: 200);
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
    ApplyChangePasswordEnabled(enabled && _isAuthenticated);
  }

  private void DumpCookies()
  {
    EnsureHttpClient();
    var uri = BaseUri;
    var sb = new StringBuilder();
    foreach (Cookie c in _cookies.GetCookies(uri))
    {
      var expires = c.Expires == DateTime.MinValue ? "session" : c.Expires.ToUniversalTime().ToString("O");
      sb.AppendLine($"{c.Name}={c.Value}; Path={c.Path}; HttpOnly={c.HttpOnly}; Secure={c.Secure}; Expires={expires}");
    }
    if (sb.Length == 0)
    {
      sb.AppendLine("Nessun cookie nel CookieContainer.");
    }
    Append(sb.ToString());
    LogEvent("Info", "Dump cookie eseguito");
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

  private sealed record LoginResponse(bool Ok, string? CsrfToken, bool? RememberIssued, string? RefreshExpiresAtUtc, bool? DeviceIssued, string? DeviceId, string? IdToken);
  private sealed record RegisterResponse(bool Ok, string? UserId, string? EmailConfirmToken, string? EmailConfirmExpiresUtc);
  private sealed record MeResponse(bool Ok, string SessionId, string UserId, string CreatedAtUtc, string ExpiresAtUtc);
  private sealed record MfaSetupResponse(bool Ok, string? Secret, string? OtpauthUri);
  private sealed record MfaRequiredResponse(bool? Ok, string? Error, string? ChallengeId);
  private sealed record MfaConfirmResponse(bool Ok, string? CsrfToken, bool? RememberIssued, string? RefreshExpiresAtUtc, bool? DeviceIssued, string? DeviceId, string? IdToken);
  private sealed record ChangePasswordResponse(bool Ok, string? Error, IEnumerable<string>? Errors, string? CsrfToken);

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
    _mfaPanel.SetQrImage(null);
    _actions.SetQrEnabled(false);
    SetState("Non autenticato", null, null, null);
    _deviceInfo.ResetInfo();
    _deviceAlert.ResetStatus();
    ClearMfa();
    _countdownTimer.Stop();
    _sessionCard.SetAvatar(null);
  }

  private void EnsureHttpClient()
  {
    if (_http != null) return;
    _cookies = new CookieContainer();
    _handler = new HttpClientHandler
    {
      CookieContainer = _cookies,
      UseCookies = true,
      ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
    };
    _http = new HttpClient(_handler);
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
    _isAuthenticated = string.Equals(state, "Autenticato", StringComparison.OrdinalIgnoreCase);
    _sessionCard.UpdateInfo(userId, sessionId, expiresAtUtc, createdAtUtc, _refreshExpiresUtc);

    string badgeText;
    System.Drawing.Color badgeColor;
    switch (state.ToLowerInvariant())
    {
      case "autenticato":
        badgeText = "Autenticato";
        badgeColor = System.Drawing.Color.SeaGreen;
        _countdownTimer.Start();
        break;
      case "sessione scaduta o revocata":
        badgeText = "Sessione scaduta/revocata";
        badgeColor = System.Drawing.Color.Peru;
        _countdownTimer.Stop();
        break;
      default:
        badgeText = "Non autenticato";
        badgeColor = System.Drawing.Color.Firebrick;
        _countdownTimer.Stop();
        break;
    }

    _statusInfo.SetStatus(state, userId, sessionId, expiresAtUtc, _rememberText, badgeColor, badgeText);
    _banner.UpdateState(state, userId);
    ApplyChangePasswordEnabled(_isAuthenticated);
    if (!_isAuthenticated)
      ResetChangePasswordForm();
  }

  private void ClearMfa()
  {
    _challengeId = null;
    _mfaPanel.ChallengeId = "";
    _actions.SetMfaEnabled(false);
    _mfaPanel.SetMfaState("MFA: -");
  }

  private void SetMfaState(string message)
  {
    _statusInfo.SetMfa(message);
  }

  private void ApplyChangePasswordEnabled(bool enabled)
  {
    _currentPasswordInput.Enabled = enabled;
    _newPasswordInput.Enabled = enabled;
    _confirmPasswordInput.Enabled = enabled;
    _actions.SetChangePasswordEnabled(enabled);
  }

  private void ResetChangePasswordForm()
  {
    _currentPasswordInput.ValueText = "";
    _newPasswordInput.ValueText = "";
    _confirmPasswordInput.ValueText = "";
  }

  private void RenderQr()
  {
    if (string.IsNullOrWhiteSpace(_otpauthUri))
    {
      _mfaPanel.SetQrImage(null);
      _actions.SetQrEnabled(false);
      return;
    }

    try
    {
      using var generator = new QRCoder.QRCodeGenerator();
      using var data = generator.CreateQrCode(_otpauthUri, QRCoder.QRCodeGenerator.ECCLevel.Q);
      using var code = new QRCoder.QRCode(data);
      var bmp = code.GetGraphic(20);
      _mfaPanel.SetQrImage(bmp);
      _actions.SetQrEnabled(true);
      Append("QR MFA generato: scansiona con Authenticator");
      LogEvent("Info", "QR MFA generato");
    }
    catch (Exception ex)
    {
      _mfaPanel.SetQrImage(null);
      LogEvent("Errore", $"QR MFA non generato: {ex.Message}");
    }
  }

  private void _actions_Load(object sender, EventArgs e)
  {

  }

  private async Task LoadProfileImageAsync(string? idToken)
  {
    if (string.IsNullOrWhiteSpace(idToken))
    {
      _sessionCard.SetAvatar(null);
      return;
    }

    try
    {
      var handler = new JwtSecurityTokenHandler { MapInboundClaims = false };
      var jwt = handler.ReadJwtToken(idToken);
      var picture = jwt.Claims.FirstOrDefault(c => c.Type == "picture")?.Value;
      if (string.IsNullOrWhiteSpace(picture))
      {
        _sessionCard.SetAvatar(null);
        return;
      }

      var image = await ImageLoader.LoadFromUrlAsync(picture, 72, 72);
      _sessionCard.SetAvatar(image);
    }
    catch (Exception ex)
    {
      _sessionCard.SetAvatar(null);
#if DEBUG
      Append($"Avatar non caricato: {ex.Message}");
#endif
    }
  }
}
