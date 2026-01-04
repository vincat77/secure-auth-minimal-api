using System.ComponentModel;
using System.Windows.Forms;

namespace WinFormsClient.Controls;

partial class ActionButtonsControl
{
    /// <summary>Required designer variable.</summary>
    private IContainer components = null!;

    private Button _registerButton = null!;
    private Button _confirmEmailButton = null!;
    private Button _loginButton = null!;
    private Button _confirmMfaButton = null!;
    private Button _refreshButton = null!;
    private Button _setupMfaButton = null!;
    private Button _disableMfaButton = null!;
    private Button _meButton = null!;
    private Button _changePasswordButton = null!;
    private Button _logoutButton = null!;
    private Button _showQrButton = null!;
    private Button _showCookiesButton = null!;
    private CheckBox _rememberCheck = null!;

    /// <summary>Clean up any resources being used.</summary>
    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            components?.Dispose();
        }
        base.Dispose(disposing);
    }

  private void InitializeComponent()
  {
    _registerButton = new Button();
    _confirmEmailButton = new Button();
    _loginButton = new Button();
    _confirmMfaButton = new Button();
    _refreshButton = new Button();
    _setupMfaButton = new Button();
    _disableMfaButton = new Button();
    _meButton = new Button();
    _changePasswordButton = new Button();
    _logoutButton = new Button();
    _showQrButton = new Button();
    _showCookiesButton = new Button();
    _rememberCheck = new CheckBox();
    SuspendLayout();
    // 
    // _registerButton
    // 
    _registerButton.Location = new Point(0, 0);
    _registerButton.Name = "_registerButton";
    _registerButton.Size = new Size(155, 30);
    _registerButton.TabIndex = 0;
    _registerButton.Text = "Registrati";
    // 
    // _confirmEmailButton
    // 
    _confirmEmailButton.Location = new Point(0, 35);
    _confirmEmailButton.Name = "_confirmEmailButton";
    _confirmEmailButton.Size = new Size(155, 30);
    _confirmEmailButton.TabIndex = 1;
    _confirmEmailButton.Text = "Conferma email";
    // 
    // _loginButton
    // 
    _loginButton.Location = new Point(0, 70);
    _loginButton.Name = "_loginButton";
    _loginButton.Size = new Size(155, 30);
    _loginButton.TabIndex = 2;
    _loginButton.Text = "Login (password)";
    // 
    // _confirmMfaButton
    // 
    _confirmMfaButton.Location = new Point(0, 105);
    _confirmMfaButton.Name = "_confirmMfaButton";
    _confirmMfaButton.Size = new Size(155, 30);
    _confirmMfaButton.TabIndex = 3;
    _confirmMfaButton.Text = "Conferma MFA";
    // 
    // _refreshButton
    // 
    _refreshButton.Location = new Point(0, 140);
    _refreshButton.Name = "_refreshButton";
    _refreshButton.Size = new Size(155, 30);
    _refreshButton.TabIndex = 4;
    _refreshButton.Text = "Refresh";
    // 
    // _setupMfaButton
    // 
    _setupMfaButton.Location = new Point(0, 175);
    _setupMfaButton.Name = "_setupMfaButton";
    _setupMfaButton.Size = new Size(155, 30);
    _setupMfaButton.TabIndex = 5;
    _setupMfaButton.Text = "Attiva MFA";
    // 
    // _disableMfaButton
    // 
    _disableMfaButton.Location = new Point(0, 210);
    _disableMfaButton.Name = "_disableMfaButton";
    _disableMfaButton.Size = new Size(155, 30);
    _disableMfaButton.TabIndex = 6;
    _disableMfaButton.Text = "Disattiva MFA";
    // 
    // _meButton
    // 
    _meButton.Location = new Point(0, 245);
    _meButton.Name = "_meButton";
    _meButton.Size = new Size(155, 30);
    _meButton.TabIndex = 7;
    _meButton.Text = "Mostra profilo";
    // 
    // _changePasswordButton
    // 
    _changePasswordButton.Location = new Point(0, 280);
    _changePasswordButton.Name = "_changePasswordButton";
    _changePasswordButton.Size = new Size(155, 30);
    _changePasswordButton.TabIndex = 8;
    _changePasswordButton.Text = "Cambia password";
    // 
    // _logoutButton
    // 
    _logoutButton.Location = new Point(0, 315);
    _logoutButton.Name = "_logoutButton";
    _logoutButton.Size = new Size(155, 30);
    _logoutButton.TabIndex = 9;
    _logoutButton.Text = "Logout";
    // 
    // _showQrButton
    // 
    _showQrButton.Location = new Point(0, 350);
    _showQrButton.Name = "_showQrButton";
    _showQrButton.Size = new Size(155, 30);
    _showQrButton.TabIndex = 10;
    _showQrButton.Text = "Mostra QR MFA";
    // 
    // _showCookiesButton
    // 
    _showCookiesButton.Location = new Point(0, 385);
    _showCookiesButton.Name = "_showCookiesButton";
    _showCookiesButton.Size = new Size(155, 30);
    _showCookiesButton.TabIndex = 11;
    _showCookiesButton.Text = "Mostra cookie";
    // 
    // _rememberCheck
    // 
    _rememberCheck.AutoSize = true;
    _rememberCheck.Location = new Point(36, 421);
    _rememberCheck.Name = "_rememberCheck";
    _rememberCheck.Size = new Size(80, 19);
    _rememberCheck.TabIndex = 12;
    _rememberCheck.Text = "Ricordami";
    // 
    // ActionButtonsControl
    // 
    AutoScaleDimensions = new SizeF(7F, 15F);
    AutoScaleMode = AutoScaleMode.Font;
    BorderStyle = BorderStyle.FixedSingle;
    Controls.Add(_changePasswordButton);
    Controls.Add(_rememberCheck);
    Controls.Add(_showCookiesButton);
    Controls.Add(_showQrButton);
    Controls.Add(_logoutButton);
    Controls.Add(_meButton);
    Controls.Add(_disableMfaButton);
    Controls.Add(_setupMfaButton);
    Controls.Add(_refreshButton);
    Controls.Add(_confirmMfaButton);
    Controls.Add(_loginButton);
    Controls.Add(_confirmEmailButton);
    Controls.Add(_registerButton);
    Name = "ActionButtonsControl";
    Size = new Size(158, 492);
    ResumeLayout(false);
    PerformLayout();
  }
}
