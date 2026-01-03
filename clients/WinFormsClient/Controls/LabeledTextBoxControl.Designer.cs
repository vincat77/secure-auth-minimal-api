using System.ComponentModel;
using System.Windows.Forms;

namespace WinFormsClient.Controls;

partial class LabeledTextBoxControl
{
    private IContainer components = null!;
    private Label _label = null!;
    private TextBox _textBox = null!;

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            components?.Dispose();
        }
        base.Dispose(disposing);
    }

    private void InitializeComponent()
    {
        components = new Container();
        _label = new Label();
        _textBox = new TextBox();
        SuspendLayout();
        // 
        // _label
        // 
        _label.AutoEllipsis = true;
        _label.AutoSize = false;
        _label.Location = new System.Drawing.Point(0, 4);
        _label.Name = "_label";
        _label.Size = new System.Drawing.Size(80, 20);
        _label.TabIndex = 0;
        _label.Text = "Label";
        _label.TextAlign = System.Drawing.ContentAlignment.MiddleLeft;
        // 
        // _textBox
        // 
        _textBox.Location = new System.Drawing.Point(90, 2);
        _textBox.Name = "_textBox";
        _textBox.Size = new System.Drawing.Size(220, 23);
        _textBox.TabIndex = 1;
        // 
        // LabeledTextBoxControl
        // 
        AutoScaleDimensions = new System.Drawing.SizeF(7F, 15F);
        AutoScaleMode = AutoScaleMode.Font;
        AutoSize = true;
        AutoSizeMode = AutoSizeMode.GrowAndShrink;
        Controls.Add(_textBox);
        Controls.Add(_label);
        Name = "LabeledTextBoxControl";
        Padding = new Padding(4);
        MinimumSize = new System.Drawing.Size(160, 27);
        Size = new System.Drawing.Size(320, 30);
        ResumeLayout(false);
        PerformLayout();
    }
}
