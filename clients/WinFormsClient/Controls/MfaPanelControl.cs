using System;
using System.Drawing;
using System.Windows.Forms;

namespace WinFormsClient.Controls;

/// <summary>
/// UserControl per challenge MFA, QR e pulsanti correlati.
/// </summary>
public partial class MfaPanelControl : UserControl
{
    public MfaPanelControl()
    {
        InitializeComponent();
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
