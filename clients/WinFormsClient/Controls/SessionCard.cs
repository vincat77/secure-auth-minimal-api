using System.Windows.Forms;

namespace WinFormsClient.Controls;

public partial class SessionCard : UserControl
{
    public SessionCard()
    {
        InitializeComponent();
    }

    public void UpdateInfo(string? userId, string? sessionId, string? expiresAtUtc, string? createdAtUtc = null, DateTime? refreshExpires = null)
    {
        _user.Text = $"Utente: {(string.IsNullOrWhiteSpace(userId) ? "-" : userId)}";
        _session.Text = $"SessionId: {(string.IsNullOrWhiteSpace(sessionId) ? "-" : sessionId)}";
        _exp.Text = $"Scadenza: {(string.IsNullOrWhiteSpace(expiresAtUtc) ? "-" : expiresAtUtc)}";
        DateTime? exp = null;
        DateTime? created = null;
        if (DateTime.TryParse(expiresAtUtc, out var expDt))
            exp = expDt.ToUniversalTime();
        if (DateTime.TryParse(createdAtUtc, out var createdDt))
            created = createdDt.ToUniversalTime();
        _countdown.SetSession(created, exp);
        _refreshCountdown.SetRefreshExpiry(refreshExpires);
    }

    public void TickCountdown()
    {
        _countdown.UpdateCountdown(TimeSpan.Zero);
        _refreshCountdown.UpdateCountdown();
    }
}
