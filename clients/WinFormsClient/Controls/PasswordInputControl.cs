using System;
using System.ComponentModel;
using System.Drawing;
using System.Windows.Forms;

namespace WinFormsClient.Controls;

/// <summary>
/// UserControl che incapsula label e textbox per la password.
/// </summary>
public sealed class PasswordInputControl : UserControl
{
    private readonly Label _label;
    private readonly TextBox _textBox;

    public PasswordInputControl()
    {
        Height = 30;
        Width = 320;

        _label = new Label
        {
            Text = "Password:",
            AutoSize = true,
            Location = new Point(0, 6)
        };

        _textBox = new TextBox
        {
            Location = new Point(90, 2),
            Width = 200,
            UseSystemPasswordChar = true,
            Name = "PasswordTextBox"
        };

        Controls.Add(_label);
        Controls.Add(_textBox);

        Anchor = AnchorStyles.Top | AnchorStyles.Left;
    }

    [Browsable(true)]
    public string PasswordText
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
