using System.ComponentModel;
using System.Drawing;
using System.Windows.Forms;

namespace WinFormsClient.Controls;

partial class SessionCard
{
    private IContainer components = null!;
    private Label _title = null!;
    private Label _user = null!;
    private Label _session = null!;
    private Label _exp = null!;
    private SessionCountdownControl _countdown = null!;
    private RefreshCountdownControl _refreshCountdown = null!;
    private PictureBox _avatar = null!;

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            components?.Dispose();
            _currentAvatar?.Dispose();
        }
        base.Dispose(disposing);
    }

    private void InitializeComponent()
    {
        components = new Container();
        _title = new Label();
        _user = new Label();
        _session = new Label();
        _exp = new Label();
        _countdown = new SessionCountdownControl();
        _refreshCountdown = new RefreshCountdownControl();
        _avatar = new PictureBox();
        SuspendLayout();
        // 
        // _title
        // 
        _title.AutoSize = true;
        _title.Font = new Font("Segoe UI", 9F, FontStyle.Bold, GraphicsUnit.Point);
        _title.Location = new System.Drawing.Point(0, 0);
        _title.Name = "_title";
        _title.Size = new System.Drawing.Size(55, 15);
        _title.TabIndex = 0;
        _title.Text = "Sessione";
        // 
        // _user
        // 
        _user.AutoSize = true;
        _user.Location = new System.Drawing.Point(0, 20);
        _user.Name = "_user";
        _user.Size = new System.Drawing.Size(50, 15);
        _user.TabIndex = 1;
        _user.Text = "Utente: -";
        // 
        // _session
        // 
        _session.AutoSize = true;
        _session.Location = new System.Drawing.Point(0, 40);
        _session.Name = "_session";
        _session.Size = new System.Drawing.Size(66, 15);
        _session.TabIndex = 2;
        _session.Text = "SessionId: -";
        // 
        // _exp
        // 
        _exp.AutoSize = true;
        _exp.Location = new System.Drawing.Point(0, 60);
        _exp.Name = "_exp";
        _exp.Size = new System.Drawing.Size(63, 15);
        _exp.TabIndex = 3;
        _exp.Text = "Scadenza: -";
        // 
        // _countdown
        // 
        _countdown.Location = new System.Drawing.Point(0, 80);
        _countdown.Name = "_countdown";
        _countdown.Size = new System.Drawing.Size(220, 50);
        _countdown.TabIndex = 4;
        // 
        // _refreshCountdown
        // 
        _refreshCountdown.Location = new System.Drawing.Point(0, 130);
        _refreshCountdown.Name = "_refreshCountdown";
        _refreshCountdown.Size = new System.Drawing.Size(220, 50);
        _refreshCountdown.TabIndex = 5;
        // 
        // _avatar
        // 
        _avatar.Location = new System.Drawing.Point(260, 0);
        _avatar.Name = "_avatar";
        _avatar.Size = new System.Drawing.Size(72, 72);
        _avatar.SizeMode = PictureBoxSizeMode.Zoom;
        _avatar.TabIndex = 6;
        _avatar.TabStop = false;
        _avatar.BackColor = System.Drawing.Color.Gainsboro;
        _avatar.BorderStyle = BorderStyle.FixedSingle;
        // 
        // SessionCard
        // 
        AutoScaleDimensions = new SizeF(7F, 15F);
        AutoScaleMode = AutoScaleMode.Font;
        BackColor = Color.FromArgb(240, 248, 255);
        BorderStyle = BorderStyle.FixedSingle;
        Controls.Add(_avatar);
        Controls.Add(_refreshCountdown);
        Controls.Add(_countdown);
        Controls.Add(_exp);
        Controls.Add(_session);
        Controls.Add(_user);
        Controls.Add(_title);
        Name = "SessionCard";
        Padding = new Padding(8);
        Size = new Size(340, 190);
        ResumeLayout(false);
        PerformLayout();
    }
}
