using System;
using System.Windows.Forms;

namespace WinFormsClient.Controls;

public sealed partial class ActionButtonsControl : UserControl
{
    public ActionButtonsControl()
    {
        InitializeComponent();
    }

    public event EventHandler? RegisterClicked;
    public event EventHandler? ConfirmEmailClicked;
    public event EventHandler? LoginClicked;
    public event EventHandler? ConfirmMfaClicked;
    public event EventHandler? RefreshClicked;
    public event EventHandler? SetupMfaClicked;
    public event EventHandler? DisableMfaClicked;
    public event EventHandler? MeClicked;
    public event EventHandler? ChangePasswordClicked;
    public event EventHandler? LogoutClicked;
    public event EventHandler? ShowQrClicked;
    public event EventHandler? ShowCookiesClicked;

    protected override void OnLoad(EventArgs e)
    {
        base.OnLoad(e);
        _registerButton.Click += (s, _) => RegisterClicked?.Invoke(this, EventArgs.Empty);
        _confirmEmailButton.Click += (s, _) => ConfirmEmailClicked?.Invoke(this, EventArgs.Empty);
        _loginButton.Click += (s, _) => LoginClicked?.Invoke(this, EventArgs.Empty);
        _confirmMfaButton.Click += (s, _) => ConfirmMfaClicked?.Invoke(this, EventArgs.Empty);
        _refreshButton.Click += (s, _) => RefreshClicked?.Invoke(this, EventArgs.Empty);
        _setupMfaButton.Click += (s, _) => SetupMfaClicked?.Invoke(this, EventArgs.Empty);
        _disableMfaButton.Click += (s, _) => DisableMfaClicked?.Invoke(this, EventArgs.Empty);
        _meButton.Click += (s, _) => MeClicked?.Invoke(this, EventArgs.Empty);
        _changePasswordButton.Click += (s, _) => ChangePasswordClicked?.Invoke(this, EventArgs.Empty);
        _logoutButton.Click += (s, _) => LogoutClicked?.Invoke(this, EventArgs.Empty);
        _showQrButton.Click += (s, _) => ShowQrClicked?.Invoke(this, EventArgs.Empty);
        _showCookiesButton.Click += (s, _) => ShowCookiesClicked?.Invoke(this, EventArgs.Empty);
    }

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
