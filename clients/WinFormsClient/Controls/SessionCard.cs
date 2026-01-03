using System.Windows.Forms;
using System.Drawing;

namespace WinFormsClient.Controls;

public partial class SessionCard : UserControl
{
    private Image? _currentAvatar;

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

    public void SetAvatar(Image? avatar)
    {
        if (!ReferenceEquals(_currentAvatar, avatar))
        {
            _currentAvatar?.Dispose();
        }

        _currentAvatar = avatar;
        _avatar.Image = avatar;
        _avatar.Visible = avatar is not null;
        _avatar.BackColor = avatar is null ? Color.Gainsboro : Color.White;
    }
}
