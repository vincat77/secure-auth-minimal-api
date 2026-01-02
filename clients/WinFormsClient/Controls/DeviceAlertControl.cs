using System;
using System.Drawing;
using System.Windows.Forms;

namespace WinFormsClient.Controls;

/// <summary>
/// Mostra l'esito dell'ultimo refresh legato al device_id (es. device mancante/mismatch).
/// </summary>
public sealed class DeviceAlertControl : UserControl
{
    private readonly Label _title = new() { Text = "Stato device/refresh", Font = new Font("Segoe UI", 9, FontStyle.Bold), AutoSize = true };
    private readonly Label _status = new() { Text = "Nessun tentativo", AutoSize = true };

    public DeviceAlertControl()
    {
        BackColor = Color.White;
        BorderStyle = BorderStyle.FixedSingle;
        Padding = new Padding(8);
        Height = 60;
        Dock = DockStyle.None;

        var panel = new Panel
        {
            Dock = DockStyle.None,
            AutoScroll = false
        };
        _title.Location = new Point(0, 0);
        _status.Location = new Point(0, 22);
        panel.Controls.Add(_title);
        panel.Controls.Add(_status);
        Controls.Add(panel);
    }

    public void SetStatus(bool success, string message)
    {
        _status.Text = message;
        _status.ForeColor = success ? Color.SeaGreen : Color.Firebrick;
    }

    public void ResetStatus()
    {
        SetStatus(success: true, message: "Nessun tentativo");
    }
}
