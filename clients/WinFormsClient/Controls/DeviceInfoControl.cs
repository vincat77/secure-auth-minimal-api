namespace WinFormsClient.Controls;

/// <summary>
/// Mostra il device_id ricevuto dal server e l'istante (locale) dell'ultimo rilascio/riuso.
/// </summary>
public partial class DeviceInfoControl : UserControl
{
    private DateTime? _lastLocal;

    public DeviceInfoControl()
    {
        InitializeComponent();
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
