using System.ComponentModel;
using System.Windows.Forms;

namespace WinFormsClient.Controls;

partial class DeviceAlertControl
{
    private IContainer components = null!;
    private Panel _panel = null!;
    private Label _title = null!;
    private Label _status = null!;

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
        _title = new Label();
        _status = new Label();
        SuspendLayout();
        // 
        // _panel
        // 
        _panel.Location = new System.Drawing.Point(0, 0);
        _panel.Name = "_panel";
        _panel.Size = new System.Drawing.Size(320, 60);
        _panel.TabIndex = 0;
        _panel.Controls.Add(_title);
        _panel.Controls.Add(_status);
        // 
        // _title
        // 
        _title.AutoSize = true;
        _title.Font = new System.Drawing.Font("Segoe UI", 9F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point);
        _title.Location = new System.Drawing.Point(0, 0);
        _title.Name = "_title";
        _title.Size = new System.Drawing.Size(112, 15);
        _title.TabIndex = 0;
        _title.Text = "Stato device/refresh";
        // 
        // _status
        // 
        _status.AutoSize = true;
        _status.Location = new System.Drawing.Point(0, 22);
        _status.Name = "_status";
        _status.Size = new System.Drawing.Size(89, 15);
        _status.TabIndex = 1;
        _status.Text = "Nessun tentativo";
        // 
        // DeviceAlertControl
        // 
        AutoScaleDimensions = new System.Drawing.SizeF(7F, 15F);
        AutoScaleMode = AutoScaleMode.Font;
        BackColor = System.Drawing.Color.White;
        BorderStyle = BorderStyle.FixedSingle;
        Controls.Add(_panel);
        Name = "DeviceAlertControl";
        Padding = new Padding(8);
        Size = new System.Drawing.Size(320, 60);
        ResumeLayout(false);
    }
}
