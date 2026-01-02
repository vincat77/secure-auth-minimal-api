using System.ComponentModel;
using System.Windows.Forms;

namespace WinFormsClient.Controls;

partial class StatusInfoControl
{
    private IContainer components = null!;
    private Label _badge = null!;
    private Label _state = null!;
    private Label _user = null!;
    private Label _session = null!;
    private Label _exp = null!;
    private Label _remember = null!;
    private Label _mfa = null!;

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
        _badge = new Label();
        _state = new Label();
        _user = new Label();
        _session = new Label();
        _exp = new Label();
        _remember = new Label();
        _mfa = new Label();
        SuspendLayout();
        // 
        // _badge
        // 
        _badge.AutoSize = true;
        _badge.BackColor = System.Drawing.Color.Firebrick;
        _badge.ForeColor = System.Drawing.Color.White;
        _badge.Location = new System.Drawing.Point(0, 0);
        _badge.Name = "_badge";
        _badge.Padding = new Padding(6);
        _badge.Size = new System.Drawing.Size(116, 27);
        _badge.TabIndex = 0;
        _badge.Text = "Non autenticato";
        // 
        // _state
        // 
        _state.AutoSize = true;
        _state.Location = new System.Drawing.Point(0, 32);
        _state.Name = "_state";
        _state.Size = new System.Drawing.Size(41, 15);
        _state.TabIndex = 1;
        _state.Text = "Stato: -";
        // 
        // _user
        // 
        _user.AutoSize = true;
        _user.Location = new System.Drawing.Point(0, 52);
        _user.Name = "_user";
        _user.Size = new System.Drawing.Size(50, 15);
        _user.TabIndex = 2;
        _user.Text = "Utente: -";
        // 
        // _session
        // 
        _session.AutoSize = true;
        _session.Location = new System.Drawing.Point(0, 72);
        _session.Name = "_session";
        _session.Size = new System.Drawing.Size(66, 15);
        _session.TabIndex = 3;
        _session.Text = "SessionId: -";
        // 
        // _exp
        // 
        _exp.AutoSize = true;
        _exp.Location = new System.Drawing.Point(0, 92);
        _exp.Name = "_exp";
        _exp.Size = new System.Drawing.Size(63, 15);
        _exp.TabIndex = 4;
        _exp.Text = "Scadenza: -";
        // 
        // _remember
        // 
        _remember.AutoSize = true;
        _remember.Location = new System.Drawing.Point(0, 112);
        _remember.Name = "_remember";
        _remember.Size = new System.Drawing.Size(72, 15);
        _remember.TabIndex = 5;
        _remember.Text = "Remember: -";
        // 
        // _mfa
        // 
        _mfa.AutoSize = true;
        _mfa.Location = new System.Drawing.Point(0, 132);
        _mfa.Name = "_mfa";
        _mfa.Size = new System.Drawing.Size(35, 15);
        _mfa.TabIndex = 6;
        _mfa.Text = "MFA: -";
        // 
        // StatusInfoControl
        // 
        AutoScaleDimensions = new System.Drawing.SizeF(7F, 15F);
        AutoScaleMode = AutoScaleMode.Font;
        Controls.Add(_mfa);
        Controls.Add(_remember);
        Controls.Add(_exp);
        Controls.Add(_session);
        Controls.Add(_user);
        Controls.Add(_state);
        Controls.Add(_badge);
        Name = "StatusInfoControl";
        Size = new System.Drawing.Size(340, 160);
        ResumeLayout(false);
        PerformLayout();
    }
}
