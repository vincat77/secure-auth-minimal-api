using System.ComponentModel;
using System.Windows.Forms;

namespace WinFormsClient.Controls;

partial class LogPanelControl
{
    private IContainer components = null!;
    private Label _label = null!;
    private TextBox _output = null!;
    private ListBox _log = null!;

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
        _output = new TextBox();
        _log = new ListBox();
        SuspendLayout();
        // 
        // _label
        // 
        _label.AutoSize = true;
        _label.Location = new System.Drawing.Point(0, 0);
        _label.Name = "_label";
        _label.Size = new System.Drawing.Size(64, 15);
        _label.TabIndex = 0;
        _label.Text = "Log eventi:";
        // 
        // _output
        // 
        _output.Location = new System.Drawing.Point(0, 20);
        _output.Multiline = true;
        _output.Name = "_output";
        _output.ReadOnly = true;
        _output.ScrollBars = ScrollBars.Vertical;
        _output.Size = new System.Drawing.Size(700, 150);
        _output.TabIndex = 1;
        // 
        // _log
        // 
        _log.FormattingEnabled = true;
        _log.ItemHeight = 15;
        _log.Location = new System.Drawing.Point(0, 180);
        _log.Name = "_log";
        _log.Size = new System.Drawing.Size(700, 139);
        _log.TabIndex = 2;
        // 
        // LogPanelControl
        // 
        AutoScaleDimensions = new System.Drawing.SizeF(7F, 15F);
        AutoScaleMode = AutoScaleMode.Font;
        Controls.Add(_log);
        Controls.Add(_output);
        Controls.Add(_label);
        Name = "LogPanelControl";
        Size = new System.Drawing.Size(720, 320);
        ResumeLayout(false);
        PerformLayout();
    }
}
