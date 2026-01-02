using System.ComponentModel;
using System.Windows.Forms;

namespace WinFormsClient.Controls;

partial class DeviceInfoControl
{
    private IContainer components = null!;
    private Panel _panel = null!;
    private Label _title = null!;
    private Label _deviceId = null!;
    private Label _issuedAt = null!;
    private Label _note = null!;

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
        _deviceId = new Label();
        _issuedAt = new Label();
        _note = new Label();
        SuspendLayout();
        // 
        // _panel
        // 
        _panel.Location = new System.Drawing.Point(0, 0);
        _panel.Name = "_panel";
        _panel.Size = new System.Drawing.Size(340, 90);
        _panel.TabIndex = 0;
        _panel.Controls.Add(_title);
        _panel.Controls.Add(_deviceId);
        _panel.Controls.Add(_issuedAt);
        _panel.Controls.Add(_note);
        // 
        // _title
        // 
        _title.AutoSize = true;
        _title.Font = new System.Drawing.Font("Segoe UI", 9F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point);
        _title.Location = new System.Drawing.Point(0, 0);
        _title.Name = "_title";
        _title.Size = new System.Drawing.Size(65, 15);
        _title.TabIndex = 0;
        _title.Text = "Dispositivo";
        // 
        // _deviceId
        // 
        _deviceId.AutoSize = true;
        _deviceId.Location = new System.Drawing.Point(0, 22);
        _deviceId.Name = "_deviceId";
        _deviceId.Size = new System.Drawing.Size(62, 15);
        _deviceId.TabIndex = 1;
        _deviceId.Text = "DeviceId: -";
        // 
        // _issuedAt
        // 
        _issuedAt.AutoSize = true;
        _issuedAt.Location = new System.Drawing.Point(0, 40);
        _issuedAt.Name = "_issuedAt";
        _issuedAt.Size = new System.Drawing.Size(125, 15);
        _issuedAt.TabIndex = 2;
        _issuedAt.Text = "Ricevuto/aggiornato: -";
        // 
        // _note
        // 
        _note.AutoSize = true;
        _note.Location = new System.Drawing.Point(0, 58);
        _note.Name = "_note";
        _note.Size = new System.Drawing.Size(42, 15);
        _note.TabIndex = 3;
        _note.Text = "Stato: -";
        // 
        // DeviceInfoControl
        // 
        AutoScaleDimensions = new System.Drawing.SizeF(7F, 15F);
        AutoScaleMode = AutoScaleMode.Font;
        BackColor = System.Drawing.Color.WhiteSmoke;
        BorderStyle = BorderStyle.FixedSingle;
        Controls.Add(_panel);
        Name = "DeviceInfoControl";
        Padding = new Padding(8);
        Size = new System.Drawing.Size(340, 90);
        ResumeLayout(false);
    }
}
