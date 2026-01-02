using System.Drawing;
using System.Windows.Forms;

namespace WinFormsClient.Controls;

public sealed class SessionCard : UserControl
{
    private readonly Label _title = new() { Text = "Sessione", Font = new Font("Segoe UI", 9, FontStyle.Bold), AutoSize = true };
    private readonly Label _user = new() { Text = "Utente: -", AutoSize = true };
    private readonly Label _session = new() { Text = "SessionId: -", AutoSize = true };
    private readonly Label _exp = new() { Text = "Scadenza: -", AutoSize = true };
    private readonly SessionCountdownControl _countdown = new();
    private readonly RefreshCountdownControl _refreshCountdown = new();

    public SessionCard()
    {
        BackColor = Color.FromArgb(240, 248, 255);
        BorderStyle = BorderStyle.FixedSingle;
        Padding = new Padding(8);
        Height = 140;
        Dock = DockStyle.None;

        Controls.Add(_title);
        Controls.Add(_user);
        Controls.Add(_session);
        Controls.Add(_exp);
        Controls.Add(_countdown);
        Controls.Add(_refreshCountdown);

        _title.Location = new Point(0, 0);
        _user.Location = new Point(0, 20);
        _session.Location = new Point(0, 40);
        _exp.Location = new Point(0, 60);
        _countdown.Location = new Point(0, 80);
        _refreshCountdown.Location = new Point(0, 110);
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
