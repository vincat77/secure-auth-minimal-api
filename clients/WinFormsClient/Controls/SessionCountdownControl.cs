namespace WinFormsClient.Controls;

/// <summary>
/// Mostra countdown e barra di avanzamento fino alla scadenza della sessione.
/// </summary>
public partial class SessionCountdownControl : UserControl
{
    private DateTime? _createdUtc;
    private DateTime? _expiresUtc;

    public SessionCountdownControl()
    {
        InitializeComponent();
    }

    public void SetSession(DateTime? createdUtc, DateTime? expiresUtc)
    {
        _createdUtc = createdUtc;
        _expiresUtc = expiresUtc;
        UpdateCountdown(TimeSpan.Zero);
    }

    public void UpdateCountdown(TimeSpan elapsedSinceUpdate)
    {
        if (!_expiresUtc.HasValue || !_createdUtc.HasValue)
        {
            _countdownLabel.Text = "Scadenza tra: -";
            _progress.Value = 0;
            _progress.ForeColor = SystemColors.Highlight;
            return;
        }

        var now = DateTime.UtcNow;
        var remaining = _expiresUtc.Value - now;
        if (remaining < TimeSpan.Zero)
        {
            remaining = TimeSpan.Zero;
        }

        var total = _expiresUtc.Value - _createdUtc.Value;
        var ratio = total <= TimeSpan.Zero ? 0 : Math.Clamp(remaining.TotalSeconds / total.TotalSeconds, 0, 1);
        var percent = (int)Math.Round(ratio * 100);
        _progress.Value = Math.Max(0, Math.Min(100, percent));

        if (ratio <= 0.2)
            _progress.ForeColor = Color.Red;
        else if (ratio <= 0.5)
            _progress.ForeColor = Color.Orange;
        else
            _progress.ForeColor = Color.SeaGreen;

        _countdownLabel.Text = $"Scadenza tra: {remaining:hh\\:mm\\:ss}";
    }
}
