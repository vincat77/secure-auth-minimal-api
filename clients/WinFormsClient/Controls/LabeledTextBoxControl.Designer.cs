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
        _label.AutoSize = true;
        _label.Location = new System.Drawing.Point(0, 6);
        _label.Name = "_label";
        _label.Size = new System.Drawing.Size(33, 15);
        _label.TabIndex = 0;
        _label.Text = "Label";
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
        Controls.Add(_textBox);
        Controls.Add(_label);
        Name = "LabeledTextBoxControl";
        Size = new System.Drawing.Size(320, 30);
        ResumeLayout(false);
        PerformLayout();
    }
}
