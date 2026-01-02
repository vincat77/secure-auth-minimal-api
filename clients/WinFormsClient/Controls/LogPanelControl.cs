using System.Windows.Forms;

namespace WinFormsClient.Controls;

/// <summary>
/// UserControl per output e log eventi.
/// </summary>
public partial class LogPanelControl : UserControl
{
    public LogPanelControl()
    {
        InitializeComponent();
    }

    public void AppendOutput(string message)
    {
        _output.AppendText($"{message}{System.Environment.NewLine}");
    }

    public void AddLog(string message, int maxItems = 200)
    {
        _log.Items.Insert(0, message);
        if (_log.Items.Count > maxItems)
        {
            _log.Items.RemoveAt(_log.Items.Count - 1);
        }
    }

    public TextBox OutputBox => _output;
    public ListBox LogBox => _log;
}
