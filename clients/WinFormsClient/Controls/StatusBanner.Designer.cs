using System.ComponentModel;
using System.Windows.Forms;

namespace WinFormsClient.Controls;

partial class StatusBanner
{
    private IContainer components = null!;
    private Panel _panel = null!;
    private Label _label = null!;

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
        _panel = new Panel();
        _label = new Label();
        // 
        // _panel
        // 
        _panel.Location = new System.Drawing.Point(0, 0);
        _panel.Name = "_panel";
        _panel.Size = new System.Drawing.Size(1200, 30);
        _panel.TabIndex = 0;
        _panel.Controls.Add(_label);
        // 
        // _label
        // 
        _label.ForeColor = System.Drawing.Color.White;
        _label.Location = new System.Drawing.Point(0, 0);
        _label.Name = "_label";
        _label.Padding = new Padding(8, 0, 0, 0);
        _label.Size = new System.Drawing.Size(1200, 30);
        _label.TabIndex = 0;
        _label.Text = "Non autenticato";
        _label.TextAlign = System.Drawing.ContentAlignment.MiddleLeft;
        SuspendLayout();
        // 
        // StatusBanner
        // 
        AutoScaleDimensions = new System.Drawing.SizeF(7F, 15F);
        AutoScaleMode = AutoScaleMode.Font;
        Controls.Add(_panel);
        Name = "StatusBanner";
        Size = new System.Drawing.Size(1200, 30);
        ResumeLayout(false);
    }
}
