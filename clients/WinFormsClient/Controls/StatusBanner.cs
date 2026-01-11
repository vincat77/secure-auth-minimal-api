namespace WinFormsClient.Controls;

public partial class StatusBanner : UserControl
{
    public StatusBanner()
    {
        InitializeComponent();
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
