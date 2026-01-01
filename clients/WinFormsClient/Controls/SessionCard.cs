using System.Drawing;
using System.Windows.Forms;

namespace WinFormsClient.Controls;

public sealed class SessionCard : UserControl
{
    private readonly Label _title = new() { Text = "Sessione", Font = new Font("Segoe UI", 9, FontStyle.Bold), AutoSize = true };
    private readonly Label _user = new() { Text = "Utente: -", AutoSize = true };
    private readonly Label _session = new() { Text = "SessionId: -", AutoSize = true };
    private readonly Label _exp = new() { Text = "Scadenza: -", AutoSize = true };

    public SessionCard()
    {
        BackColor = Color.FromArgb(240, 248, 255);
        BorderStyle = BorderStyle.FixedSingle;
        Padding = new Padding(8);
        Height = 90;
        Dock = DockStyle.Fill;

        var layout = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.TopDown,
            AutoSize = true,
            WrapContents = false
        };
        layout.Controls.AddRange(new Control[] { _title, _user, _session, _exp });
        Controls.Add(layout);
    }

    public void UpdateInfo(string? userId, string? sessionId, string? expiresAtUtc)
    {
        _user.Text = $"Utente: {(string.IsNullOrWhiteSpace(userId) ? "-" : userId)}";
        _session.Text = $"SessionId: {(string.IsNullOrWhiteSpace(sessionId) ? "-" : sessionId)}";
        _exp.Text = $"Scadenza: {(string.IsNullOrWhiteSpace(expiresAtUtc) ? "-" : expiresAtUtc)}";
    }
}
