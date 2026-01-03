using System.ComponentModel;
using System.Drawing;
using System.Windows.Forms;

namespace WinFormsClient.Controls;

/// <summary>
/// UserControl semplice: label + textbox.
/// </summary>
public partial class LabeledTextBoxControl : UserControl
{
    private const int Spacing = 6;
    private const int MinTextBoxWidth = 80;

    public LabeledTextBoxControl()
    {
        InitializeComponent();
        SetStyle(ControlStyles.ResizeRedraw, true);
    }

    [Browsable(true)]
    public string LabelText
    {
        get => _label.Text;
        set
        {
            _label.Text = value;
            LayoutChildren();
        }
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

    public override Size GetPreferredSize(Size proposedSize)
    {
        var padding = Padding;
        var labelSize = GetLabelPreferredSize();
        var textSize = _textBox.GetPreferredSize(Size.Empty);

        var desiredWidth = padding.Horizontal + labelSize.Width + Spacing + Math.Max(textSize.Width, MinTextBoxWidth);
        var desiredHeight = padding.Vertical + Math.Max(labelSize.Height, textSize.Height);

        if (proposedSize.Width > 0)
        {
            desiredWidth = Math.Max(desiredWidth, proposedSize.Width);
        }

        if (proposedSize.Height > 0)
        {
            desiredHeight = Math.Max(desiredHeight, proposedSize.Height);
        }

        return new Size(desiredWidth, desiredHeight);
    }

    protected override void OnLayout(LayoutEventArgs e)
    {
        base.OnLayout(e);
        LayoutChildren();
    }

    protected override void OnSizeChanged(EventArgs e)
    {
        base.OnSizeChanged(e);
        LayoutChildren();
    }

    protected override void OnFontChanged(EventArgs e)
    {
        base.OnFontChanged(e);
        LayoutChildren();
    }

    protected override void OnPaddingChanged(EventArgs e)
    {
        base.OnPaddingChanged(e);
        LayoutChildren();
    }

    private void LayoutChildren()
    {
        if (_label == null || _textBox == null)
        {
            return;
        }

        var padding = Padding;
        var labelPreferredSize = GetLabelPreferredSize();
        var textPreferredSize = _textBox.GetPreferredSize(Size.Empty);
        var textPreferredHeight = textPreferredSize.Height;

        var availableWidth = Math.Max(0, Width - padding.Horizontal);
        var spacing = availableWidth >= MinTextBoxWidth + Spacing
            ? Spacing
            : Math.Max(0, availableWidth - MinTextBoxWidth);

        var maxLabelWidth = Math.Max(0, availableWidth - spacing - MinTextBoxWidth);
        var labelWidth = Math.Min(labelPreferredSize.Width, maxLabelWidth);

        _label.Size = new Size(labelWidth, labelPreferredSize.Height);

        var textBoxWidth = Math.Max(MinTextBoxWidth, Math.Max(0, availableWidth - spacing - labelWidth));

        var combinedHeight = Math.Max(_label.Height, textPreferredHeight);
        var verticalOffset = padding.Top + Math.Max(0, (Height - padding.Vertical - combinedHeight) / 2);

        _label.Location = new Point(
            padding.Left,
            verticalOffset + (combinedHeight - _label.Height) / 2);

        _textBox.Size = new Size(textBoxWidth, textPreferredHeight);
        _textBox.Location = new Point(
            padding.Left + labelWidth + spacing,
            verticalOffset + (combinedHeight - _textBox.Height) / 2);
    }

    private Size GetLabelPreferredSize()
    {
        return TextRenderer.MeasureText(_label.Text, _label.Font, new Size(int.MaxValue, int.MaxValue), TextFormatFlags.SingleLine);
    }
}
