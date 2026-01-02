using System;
using System.Windows.Forms;

namespace WinFormsClient.Controls;

/// <summary>
/// UserControl con i pulsanti di azione principali e la checkbox Remember.
/// </summary>
public sealed class ActionButtonsControl : UserControl
{
    private readonly Button _registerButton = new() { Text = "Registrati", Width = 155, Height = 30 };
    private readonly Button _confirmEmailButton = new() { Text = "Conferma email", Width = 155, Height = 30 };
    private readonly Button _loginButton = new() { Text = "Login (password)", Width = 155, Height = 30 };
    private readonly Button _confirmMfaButton = new() { Text = "Conferma MFA", Width = 155, Height = 30 };
    private readonly Button _refreshButton = new() { Text = "Refresh", Width = 155, Height = 30 };
    private readonly Button _setupMfaButton = new() { Text = "Attiva MFA", Width = 155, Height = 30 };
    private readonly Button _disableMfaButton = new() { Text = "Disattiva MFA", Width = 155, Height = 30 };
    private readonly Button _meButton = new() { Text = "Mostra profilo", Width = 155, Height = 30 };
    private readonly Button _logoutButton = new() { Text = "Logout", Width = 155, Height = 30 };
    private readonly Button _showQrButton = new() { Text = "Mostra QR MFA", Width = 155, Height = 30 };
    private readonly CheckBox _rememberCheck = new() { Text = "Ricordami", AutoSize = true };

    public ActionButtonsControl()
    {
        Height = 320;
        Width = 180;
        // Posizionamento verticale fisso.
        int x = 0;
        int y = 0;
        int step = 35;

        _registerButton.Location = new System.Drawing.Point(x, y); y += step;
        _confirmEmailButton.Location = new System.Drawing.Point(x, y); y += step;
        _loginButton.Location = new System.Drawing.Point(x, y); y += step;
        _confirmMfaButton.Location = new System.Drawing.Point(x, y); y += step;
        _refreshButton.Location = new System.Drawing.Point(x, y); y += step;
        _setupMfaButton.Location = new System.Drawing.Point(x, y); y += step;
        _disableMfaButton.Location = new System.Drawing.Point(x, y); y += step;
        _meButton.Location = new System.Drawing.Point(x, y); y += step;
        _logoutButton.Location = new System.Drawing.Point(x, y); y += step;
        _showQrButton.Location = new System.Drawing.Point(x, y); y += step;
        _rememberCheck.Location = new System.Drawing.Point(x, y + 5);

        Controls.AddRange(new Control[]
        {
            _registerButton,_confirmEmailButton,_loginButton,_confirmMfaButton,_refreshButton,_setupMfaButton,
            _disableMfaButton,_meButton,_logoutButton,_showQrButton,_rememberCheck
        });

        _registerButton.Click += (s, e) => RegisterClicked?.Invoke(this, EventArgs.Empty);
        _confirmEmailButton.Click += (s, e) => ConfirmEmailClicked?.Invoke(this, EventArgs.Empty);
        _loginButton.Click += (s, e) => LoginClicked?.Invoke(this, EventArgs.Empty);
        _confirmMfaButton.Click += (s, e) => ConfirmMfaClicked?.Invoke(this, EventArgs.Empty);
        _refreshButton.Click += (s, e) => RefreshClicked?.Invoke(this, EventArgs.Empty);
        _setupMfaButton.Click += (s, e) => SetupMfaClicked?.Invoke(this, EventArgs.Empty);
        _disableMfaButton.Click += (s, e) => DisableMfaClicked?.Invoke(this, EventArgs.Empty);
        _meButton.Click += (s, e) => MeClicked?.Invoke(this, EventArgs.Empty);
        _logoutButton.Click += (s, e) => LogoutClicked?.Invoke(this, EventArgs.Empty);
        _showQrButton.Click += (s, e) => ShowQrClicked?.Invoke(this, EventArgs.Empty);
    }

    public event EventHandler? RegisterClicked;
    public event EventHandler? ConfirmEmailClicked;
    public event EventHandler? LoginClicked;
    public event EventHandler? ConfirmMfaClicked;
    public event EventHandler? RefreshClicked;
    public event EventHandler? SetupMfaClicked;
    public event EventHandler? DisableMfaClicked;
    public event EventHandler? MeClicked;
    public event EventHandler? LogoutClicked;
    public event EventHandler? ShowQrClicked;

    public bool RememberChecked
    {
        get => _rememberCheck.Checked;
        set => _rememberCheck.Checked = value;
    }

    public void SetEnabled(bool enabled)
    {
        foreach (Control c in Controls)
        {
            c.Enabled = enabled;
        }
    }

    public void SetMfaEnabled(bool enabled) => _confirmMfaButton.Enabled = enabled;
    public void SetQrEnabled(bool enabled) => _showQrButton.Enabled = enabled;
}
