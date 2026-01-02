using System.Drawing;
using System.Windows.Forms;

namespace WinFormsClient.Controls;

/// <summary>
/// Mostra lo stato utente/sessione con badge e informazioni collegate.
/// </summary>
public sealed class StatusInfoControl : UserControl
{
    private readonly Label _badge = new() { AutoSize = true, Padding = new Padding(6), BackColor = Color.Firebrick, ForeColor = Color.White, Text = "Non autenticato" };
    private readonly Label _state = new() { Text = "Stato: -", AutoSize = true };
    private readonly Label _user = new() { Text = "Utente: -", AutoSize = true };
    private readonly Label _session = new() { Text = "SessionId: -", AutoSize = true };
    private readonly Label _exp = new() { Text = "Scadenza: -", AutoSize = true };
    private readonly Label _remember = new() { Text = "Remember: -", AutoSize = true };
    private readonly Label _mfa = new() { Text = "MFA: -", AutoSize = true };

    public StatusInfoControl()
    {
        Height = 180;
        Width = 340;
        Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;

        _badge.Location = new Point(0, 0);
        _state.Location = new Point(0, 32);
        _user.Location = new Point(0, 52);
        _session.Location = new Point(0, 72);
        _exp.Location = new Point(0, 92);
        _remember.Location = new Point(0, 112);
        _mfa.Location = new Point(0, 132);

        Controls.Add(_badge);
        Controls.Add(_state);
        Controls.Add(_user);
        Controls.Add(_session);
        Controls.Add(_exp);
        Controls.Add(_remember);
        Controls.Add(_mfa);
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
