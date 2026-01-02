using System.Windows.Forms;

namespace WinFormsClient.Controls;

/// <summary>
/// UserControl per output e log eventi.
/// </summary>
public sealed class LogPanelControl : UserControl
{
    private readonly Label _label;
    private readonly TextBox _output;
    private readonly ListBox _log;

    public LogPanelControl()
    {
        Height = 320;
        Width = 720;

        _label = new Label { Text = "Log eventi:", AutoSize = true, Location = new System.Drawing.Point(0, 0) };
        _output = new TextBox
        {
            Multiline = true,
            ReadOnly = true,
            ScrollBars = ScrollBars.Vertical,
            Width = 700,
            Height = 150,
            Location = new System.Drawing.Point(0, 20)
        };
        _log = new ListBox
        {
            Width = 700,
            Height = 140,
            Location = new System.Drawing.Point(0, 180)
        };

        Controls.Add(_label);
        Controls.Add(_output);
        Controls.Add(_log);
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
