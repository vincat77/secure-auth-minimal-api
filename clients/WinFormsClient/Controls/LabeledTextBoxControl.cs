using System.ComponentModel;
using System.Windows.Forms;

namespace WinFormsClient.Controls;

/// <summary>
/// UserControl semplice: label + textbox.
/// </summary>
public partial class LabeledTextBoxControl : UserControl
{
    public LabeledTextBoxControl()
    {
        InitializeComponent();
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

    [Browsable(true)]
    public bool UseSystemPasswordChar
    {
        get => _textBox.UseSystemPasswordChar;
        set => _textBox.UseSystemPasswordChar = value;
    }
}
