using System;
using System.Drawing;
using System.Windows.Forms;

namespace WinFormsClient.Controls;

/// <summary>
/// Countdown e barra per la scadenza del refresh token (remember me).
/// </summary>
public sealed class RefreshCountdownControl : UserControl
{
    private readonly Label _label = new() { Text = "Refresh: -", AutoSize = true };
    private readonly ProgressBar _progress = new() { Dock = DockStyle.None, Height = 14 };
    private DateTime? _expiresUtc;

    public RefreshCountdownControl()
    {
        Height = 50;
        Dock = DockStyle.None;
        Controls.Add(_label);
        Controls.Add(_progress);
        _label.Location = new Point(0, 0);
        _progress.Location = new Point(0, 20);
        _progress.Width = 200;
    }

    public void SetRefreshExpiry(DateTime? expiresUtc)
    {
        _expiresUtc = expiresUtc;
        UpdateCountdown();
    }

    public void UpdateCountdown()
    {
        if (!_expiresUtc.HasValue)
        {
            _label.Text = "Refresh: -";
            _progress.Value = 0;
            return;
        }

        var now = DateTime.UtcNow;
        var remaining = _expiresUtc.Value - now;
        if (remaining < TimeSpan.Zero)
            remaining = TimeSpan.Zero;

        // Progress non conosce il created; stimiamo dal max-age residuo vs totale se già calcolato altrove (qui usiamo solo countdown).
        var percent = remaining.TotalSeconds > 0 ? Math.Min(100, Math.Max(0, (int)Math.Round((remaining.TotalHours / 24.0) * 100))) : 0;
        _progress.Value = Math.Max(0, Math.Min(100, percent));
        _label.Text = $"Refresh: {remaining:dd\\:hh\\:mm\\:ss}";
    }
}
