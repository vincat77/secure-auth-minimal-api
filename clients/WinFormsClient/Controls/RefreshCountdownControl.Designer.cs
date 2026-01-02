using System.ComponentModel;
using System.Windows.Forms;

namespace WinFormsClient.Controls;

partial class RefreshCountdownControl
{
    private IContainer components = null!;
    private Label _label = null!;
    private ProgressBar _progress = null!;

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
        _progress = new ProgressBar();
        SuspendLayout();
        // 
        // _label
        // 
        _label.AutoSize = true;
        _label.Location = new System.Drawing.Point(0, 0);
        _label.Name = "_label";
        _label.Size = new System.Drawing.Size(61, 15);
        _label.TabIndex = 0;
        _label.Text = "Refresh: -";
        // 
        // _progress
        // 
        _progress.Location = new System.Drawing.Point(0, 20);
        _progress.Name = "_progress";
        _progress.Size = new System.Drawing.Size(200, 14);
        _progress.TabIndex = 1;
        // 
        // RefreshCountdownControl
        // 
        AutoScaleDimensions = new System.Drawing.SizeF(7F, 15F);
        AutoScaleMode = AutoScaleMode.Font;
        Controls.Add(_progress);
        Controls.Add(_label);
        Name = "RefreshCountdownControl";
        Size = new System.Drawing.Size(220, 50);
        ResumeLayout(false);
        PerformLayout();
    }
}
