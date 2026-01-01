using System;
using System.Drawing;
using System.Windows.Forms;

namespace WinFormsClient.Controls;

/// <summary>
/// Mostra il device_id ricevuto dal server e l'istante (locale) dell'ultimo rilascio/riuso.
/// </summary>
public sealed class DeviceInfoControl : UserControl
{
    private readonly Label _title = new() { Text = "Dispositivo", Font = new Font("Segoe UI", 9, FontStyle.Bold), AutoSize = true };
    private readonly Label _deviceId = new() { Text = "DeviceId: -", AutoSize = true };
    private readonly Label _issuedAt = new() { Text = "Ricevuto/aggiornato: -", AutoSize = true };
    private readonly Label _note = new() { Text = "Stato: -", AutoSize = true };
    private DateTime? _lastLocal;

    public DeviceInfoControl()
    {
        BackColor = Color.WhiteSmoke;
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
        layout.Controls.AddRange(new Control[] { _title, _deviceId, _issuedAt, _note });
        Controls.Add(layout);
    }

    /// <summary>
    /// Aggiorna il pannello con l'ultimo device_id noto e se è stato appena emesso.
    /// </summary>
    public void UpdateDevice(string? deviceId, bool? issuedNow = null)
    {
        if (string.IsNullOrWhiteSpace(deviceId))
        {
            _deviceId.Text = "DeviceId: -";
            _issuedAt.Text = "Ricevuto/aggiornato: -";
            _note.Text = "Stato: nessun device_id ricevuto";
            _lastLocal = null;
            return;
        }

        _deviceId.Text = $"DeviceId: {deviceId}";
        _lastLocal = DateTime.Now;
        _issuedAt.Text = $"Ricevuto/aggiornato: {_lastLocal:HH:mm:ss}";
        _note.Text = issuedNow == true
            ? "Stato: nuovo device registrato"
            : "Stato: device riutilizzato";
    }

    /// <summary>
    /// Resetta i campi (usato su logout/reset client).
    /// </summary>
    public void ResetInfo()
    {
        UpdateDevice(null, null);
    }
}
