using System.ComponentModel;
using System.Windows.Forms;

namespace WinFormsClient.Controls;

partial class MfaPanelControl
{
    private IContainer components = null!;
    private Label _label = null!;
    private TextBox _challengeBox = null!;
    private TextBox _totpBox = null!;
    private Button _confirmMfaButton = null!;
    private Button _setupMfaButton = null!;
    private Button _disableMfaButton = null!;
    private Button _showQrButton = null!;
    private PictureBox _qrBox = null!;
    private Label _mfaStatus = null!;

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
        _challengeBox = new TextBox();
        _totpBox = new TextBox();
        _confirmMfaButton = new Button();
        _setupMfaButton = new Button();
        _disableMfaButton = new Button();
        _showQrButton = new Button();
        _qrBox = new PictureBox();
        _mfaStatus = new Label();
        ((ISupportInitialize)_qrBox).BeginInit();
        SuspendLayout();
        // 
        // _label
        // 
        _label.AutoSize = true;
        _label.Location = new System.Drawing.Point(0, 6);
        _label.Name = "_label";
        _label.Size = new System.Drawing.Size(87, 15);
        _label.TabIndex = 0;
        _label.Text = "Challenge MFA:";
        // 
        // _challengeBox
        // 
        _challengeBox.Location = new System.Drawing.Point(120, 2);
        _challengeBox.Name = "_challengeBox";
        _challengeBox.ReadOnly = true;
        _challengeBox.Size = new System.Drawing.Size(180, 23);
        _challengeBox.TabIndex = 1;
        // 
        // _totpBox
        // 
        _totpBox.Location = new System.Drawing.Point(120, 32);
        _totpBox.Name = "_totpBox";
        _totpBox.PlaceholderText = "TOTP (se richiesto)";
        _totpBox.Size = new System.Drawing.Size(180, 23);
        _totpBox.TabIndex = 2;
        // 
        // _confirmMfaButton
        // 
        _confirmMfaButton.Location = new System.Drawing.Point(0, 70);
        _confirmMfaButton.Name = "_confirmMfaButton";
        _confirmMfaButton.Size = new System.Drawing.Size(155, 30);
        _confirmMfaButton.TabIndex = 3;
        _confirmMfaButton.Text = "Conferma MFA";
        _confirmMfaButton.UseVisualStyleBackColor = true;
        // 
        // _setupMfaButton
        // 
        _setupMfaButton.Location = new System.Drawing.Point(0, 105);
        _setupMfaButton.Name = "_setupMfaButton";
        _setupMfaButton.Size = new System.Drawing.Size(155, 30);
        _setupMfaButton.TabIndex = 4;
        _setupMfaButton.Text = "Attiva MFA";
        _setupMfaButton.UseVisualStyleBackColor = true;
        // 
        // _disableMfaButton
        // 
        _disableMfaButton.Location = new System.Drawing.Point(0, 140);
        _disableMfaButton.Name = "_disableMfaButton";
        _disableMfaButton.Size = new System.Drawing.Size(155, 30);
        _disableMfaButton.TabIndex = 5;
        _disableMfaButton.Text = "Disattiva MFA";
        _disableMfaButton.UseVisualStyleBackColor = true;
        // 
        // _showQrButton
        // 
        _showQrButton.Location = new System.Drawing.Point(0, 175);
        _showQrButton.Name = "_showQrButton";
        _showQrButton.Size = new System.Drawing.Size(155, 30);
        _showQrButton.TabIndex = 6;
        _showQrButton.Text = "Mostra QR MFA";
        _showQrButton.UseVisualStyleBackColor = true;
        // 
        // _qrBox
        // 
        _qrBox.BackColor = System.Drawing.Color.White;
        _qrBox.BorderStyle = BorderStyle.FixedSingle;
        _qrBox.Location = new System.Drawing.Point(200, 60);
        _qrBox.Name = "_qrBox";
        _qrBox.Size = new System.Drawing.Size(160, 160);
        _qrBox.SizeMode = PictureBoxSizeMode.StretchImage;
        _qrBox.TabIndex = 7;
        _qrBox.TabStop = false;
        // 
        // _mfaStatus
        // 
        _mfaStatus.AutoSize = true;
        _mfaStatus.Location = new System.Drawing.Point(0, 215);
        _mfaStatus.Name = "_mfaStatus";
        _mfaStatus.Size = new System.Drawing.Size(35, 15);
        _mfaStatus.TabIndex = 8;
        _mfaStatus.Text = "MFA: -";
        // 
        // MfaPanelControl
        // 
        AutoScaleDimensions = new System.Drawing.SizeF(7F, 15F);
        AutoScaleMode = AutoScaleMode.Font;
        Controls.Add(_mfaStatus);
        Controls.Add(_qrBox);
        Controls.Add(_showQrButton);
        Controls.Add(_disableMfaButton);
        Controls.Add(_setupMfaButton);
        Controls.Add(_confirmMfaButton);
        Controls.Add(_totpBox);
        Controls.Add(_challengeBox);
        Controls.Add(_label);
        Name = "MfaPanelControl";
        Size = new System.Drawing.Size(520, 260);
        ((ISupportInitialize)_qrBox).EndInit();
        ResumeLayout(false);
        PerformLayout();
    }
}
