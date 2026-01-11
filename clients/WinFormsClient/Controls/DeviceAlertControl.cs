namespace WinFormsClient.Controls;

/// <summary>
/// Mostra l'esito dell'ultimo refresh legato al device_id (es. device mancante/mismatch).
/// </summary>
public partial class DeviceAlertControl : UserControl
{
    public DeviceAlertControl()
    {
        InitializeComponent();
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
