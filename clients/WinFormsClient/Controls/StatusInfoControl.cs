using System.Drawing;
using System.Windows.Forms;

namespace WinFormsClient.Controls;

/// <summary>
/// Mostra lo stato utente/sessione con badge e informazioni collegate.
/// </summary>
public partial class StatusInfoControl : UserControl
{
    public StatusInfoControl()
    {
        InitializeComponent();
    }

    public void SetStatus(string stateText, string? userId, string? sessionId, string? expiresAtUtc, string? rememberText, Color badgeColor, string badgeText)
    {
        _state.Text = $"Stato: {stateText}";
        _user.Text = $"Utente: {(string.IsNullOrWhiteSpace(userId) ? "-" : userId)}";
        _session.Text = $"SessionId: {(string.IsNullOrWhiteSpace(sessionId) ? "-" : sessionId)}";
        _exp.Text = $"Scadenza: {(string.IsNullOrWhiteSpace(expiresAtUtc) ? "-" : expiresAtUtc)}";
        _remember.Text = $"Remember: {(string.IsNullOrWhiteSpace(rememberText) ? "-" : rememberText)}";
        _badge.Text = badgeText;
        _badge.BackColor = badgeColor;
    }

    public void SetMfa(string text) => _mfa.Text = text;

    public void SetRemember(string text) => _remember.Text = $"Remember: {text}";
}
