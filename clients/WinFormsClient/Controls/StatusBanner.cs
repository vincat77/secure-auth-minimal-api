using System.Drawing;
using System.Windows.Forms;

namespace WinFormsClient.Controls;

public sealed class StatusBanner : UserControl
{
    private readonly Panel _panel = new() { Dock = DockStyle.Fill };
    private readonly Label _label = new() { Dock = DockStyle.Fill, ForeColor = Color.White, TextAlign = ContentAlignment.MiddleLeft, Padding = new Padding(8, 0, 0, 0) };

    public StatusBanner()
    {
        Height = 30;
        Dock = DockStyle.Top;
        _panel.Controls.Add(_label);
        Controls.Add(_panel);
        UpdateState("Non autenticato", null);
    }

    public void UpdateState(string state, string? userId)
    {
        switch (state.ToLowerInvariant())
        {
            case "autenticato":
                _panel.BackColor = Color.SeaGreen;
                _label.Text = $"Loggato come {(string.IsNullOrWhiteSpace(userId) ? "-" : userId)}";
                break;
            case "sessione scaduta o revocata":
                _panel.BackColor = Color.Peru;
                _label.Text = "Sessione scaduta o revocata";
                break;
            default:
                _panel.BackColor = Color.Firebrick;
                _label.Text = "Non autenticato";
                break;
        }
    }
}
