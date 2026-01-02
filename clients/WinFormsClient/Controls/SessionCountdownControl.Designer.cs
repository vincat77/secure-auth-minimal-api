using System.ComponentModel;
using System.Windows.Forms;

namespace WinFormsClient.Controls;

partial class SessionCountdownControl
{
    private IContainer components = null!;
    private Label _countdownLabel = null!;
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
        _countdownLabel = new Label();
        _progress = new ProgressBar();
        SuspendLayout();
        // 
        // _countdownLabel
        // 
        _countdownLabel.AutoSize = true;
        _countdownLabel.Location = new System.Drawing.Point(0, 0);
        _countdownLabel.Name = "_countdownLabel";
        _countdownLabel.Size = new System.Drawing.Size(82, 15);
        _countdownLabel.TabIndex = 0;
        _countdownLabel.Text = "Scadenza tra: -";
        // 
        // _progress
        // 
        _progress.Location = new System.Drawing.Point(0, 20);
        _progress.Name = "_progress";
        _progress.Size = new System.Drawing.Size(200, 14);
        _progress.TabIndex = 1;
        // 
        // SessionCountdownControl
        // 
        AutoScaleDimensions = new System.Drawing.SizeF(7F, 15F);
        AutoScaleMode = AutoScaleMode.Font;
        Controls.Add(_progress);
        Controls.Add(_countdownLabel);
        Name = "SessionCountdownControl";
        Size = new System.Drawing.Size(220, 50);
        ResumeLayout(false);
        PerformLayout();
    }
}
