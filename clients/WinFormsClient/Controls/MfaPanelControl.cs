using System;
using System.Drawing;
using System.Windows.Forms;

namespace WinFormsClient.Controls;

/// <summary>
/// UserControl per challenge MFA, QR e pulsanti correlati.
/// </summary>
public sealed class MfaPanelControl : UserControl
{
    private readonly Label _label = new() { Text = "Challenge MFA:", AutoSize = true };
    private readonly TextBox _challengeBox = new() { ReadOnly = true, Width = 180 };
    private readonly TextBox _totpBox = new() { PlaceholderText = "TOTP (se richiesto)", Width = 180 };
    private readonly Button _confirmMfaButton = new() { Text = "Conferma MFA", Width = 155, Height = 30 };
    private readonly Button _setupMfaButton = new() { Text = "Attiva MFA", Width = 155, Height = 30 };
    private readonly Button _disableMfaButton = new() { Text = "Disattiva MFA", Width = 155, Height = 30 };
    private readonly Button _showQrButton = new() { Text = "Mostra QR MFA", Width = 155, Height = 30 };
    private readonly PictureBox _qrBox = new() { SizeMode = PictureBoxSizeMode.StretchImage, Width = 160, Height = 160, BorderStyle = BorderStyle.FixedSingle, BackColor = Color.White };
    private readonly Label _mfaStatus = new() { Text = "MFA: -", AutoSize = true };

    public MfaPanelControl()
    {
        Height = 360;
        Width = 520;

        _label.Location = new Point(0, 0);
        _challengeBox.Location = new Point(120, 0);
        _totpBox.Location = new Point(120, 30);
        _confirmMfaButton.Location = new Point(0, 70);
        _setupMfaButton.Location = new Point(0, 105);
        _disableMfaButton.Location = new Point(0, 140);
        _showQrButton.Location = new Point(0, 175);
        _qrBox.Location = new Point(200, 35);
        _mfaStatus.Location = new Point(0, 210);

        Controls.Add(_label);
        Controls.Add(_challengeBox);
        Controls.Add(_totpBox);
        Controls.Add(_confirmMfaButton);
        Controls.Add(_setupMfaButton);
        Controls.Add(_disableMfaButton);
        Controls.Add(_showQrButton);
        Controls.Add(_qrBox);
        Controls.Add(_mfaStatus);

        _confirmMfaButton.Click += (s, e) => ConfirmMfaClicked?.Invoke(this, EventArgs.Empty);
        _setupMfaButton.Click += (s, e) => SetupMfaClicked?.Invoke(this, EventArgs.Empty);
        _disableMfaButton.Click += (s, e) => DisableMfaClicked?.Invoke(this, EventArgs.Empty);
        _showQrButton.Click += (s, e) => ShowQrClicked?.Invoke(this, EventArgs.Empty);
    }

    public event EventHandler? ConfirmMfaClicked;
    public event EventHandler? SetupMfaClicked;
    public event EventHandler? DisableMfaClicked;
    public event EventHandler? ShowQrClicked;

    public string? ChallengeId
    {
        get => _challengeBox.Text;
        set => _challengeBox.Text = value ?? string.Empty;
    }

    public string TotpCode
    {
        get => _totpBox.Text;
        set => _totpBox.Text = value ?? string.Empty;
    }

    public void SetMfaState(string text) => _mfaStatus.Text = text;

    public void SetQrImage(Image? image) => _qrBox.Image = image;

    public void SetMfaEnabled(bool enabled) => _confirmMfaButton.Enabled = enabled;

    public void SetQrEnabled(bool enabled) => _showQrButton.Enabled = enabled;

    public void SetButtonsEnabled(bool enabled)
    {
        _confirmMfaButton.Enabled = enabled;
        _setupMfaButton.Enabled = enabled;
        _disableMfaButton.Enabled = enabled;
        _showQrButton.Enabled = enabled;
    }
}
