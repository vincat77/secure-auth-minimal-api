namespace WinFormsClient.Controls;

/// <summary>
/// Countdown e barra per la scadenza del refresh token (remember me).
/// </summary>
public partial class RefreshCountdownControl : UserControl
{
    private DateTime? _expiresUtc;

    public RefreshCountdownControl()
    {
        InitializeComponent();
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

        var percent = remaining.TotalSeconds > 0 ? Math.Min(100, Math.Max(0, (int)Math.Round((remaining.TotalHours / 24.0) * 100))) : 0;
        _progress.Value = Math.Max(0, Math.Min(100, percent));
        _label.Text = $"Refresh: {remaining:dd\\:hh\\:mm\\:ss}";
    }
}
