using System;
using System.ComponentModel;
using System.Drawing;
using System.Windows.Forms;

namespace WinFormsClient.Controls;

/// <summary>
/// UserControl semplice: label + textbox.
/// </summary>
public sealed class LabeledTextBoxControl : UserControl
{
    private readonly Label _label;
    private readonly TextBox _textBox;

    public LabeledTextBoxControl()
    {
        Height = 30;
        Width = 320;

        _label = new Label
        {
            Text = "Label",
            AutoSize = true,
            Location = new Point(0, 6)
        };

        _textBox = new TextBox
        {
            Location = new Point(90, 2),
            Width = 220,
            Name = "ValueTextBox"
        };

        Controls.Add(_label);
        Controls.Add(_textBox);
        Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
    }

    [Browsable(true)]
    public string LabelText
    {
        get => _label.Text;
        set => _label.Text = value;
    }

    [Browsable(true)]
    public string ValueText
    {
        get => _textBox.Text;
        set => _textBox.Text = value;
    }
}
