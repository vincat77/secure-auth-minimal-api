using System;
using System.ComponentModel;
using System.Drawing;
using System.Windows.Forms;

namespace WinFormsClient.Controls;

/// <summary>
/// UserControl per la base URL.
/// </summary>
public sealed class UrlInputControl : UserControl
{
    private readonly Label _label;
    private readonly TextBox _textBox;

    public UrlInputControl()
    {
        Height = 32;
        Width = 500;

        _label = new Label
        {
            Text = "Base URL:",
            AutoSize = true,
            Location = new Point(0, 6)
        };

        _textBox = new TextBox
        {
            Location = new Point(90, 2),
            Width = 380,
            Name = "UrlTextBox"
        };

        Controls.Add(_label);
        Controls.Add(_textBox);
        Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
    }

    [Browsable(true)]
    public string UrlText
    {
        get => _textBox.Text;
        set => _textBox.Text = value;
    }

    [Browsable(true)]
    public string LabelText
    {
        get => _label.Text;
        set => _label.Text = value;
    }
}
