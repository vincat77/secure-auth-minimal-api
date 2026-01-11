using System.ComponentModel;
using System.Windows.Forms;

namespace WinFORM_AUTH_Client;

partial class MainForm
{
    /// <summary>
    ///  Required designer variable.
    /// </summary>
    private IContainer components = null!;

    private TextBox txtBaseUrl = null!;
    private TextBox txtOtpauth = null!;
    private TextBox txtTotp = null!;
    private TextBox txtLog = null!;
    private Button btnRunFlow = null!;
    private Button btnRegister = null!;
    private Button btnConfirmEmail = null!;
    private Button btnLoginPwd = null!;
    private Button btnSetupMfa = null!;
    private Button btnLogout = null!;
    private Button btnLoginMfa = null!;
    private Button btnConfirmMfa = null!;
    private Button btnMe = null!;
    private Button btnRegenChallenge = null!;
    private Button btnPasswordReset = null!;
    private Label lblBaseUrl = null!;
    private Label lblOtpauth = null!;
    private Label lblTotp = null!;

    /// <summary>
    ///  Clean up any resources being used.
    /// </summary>
    protected override void Dispose(bool disposing)
    {
        if (disposing && (components != null))
        {
            components.Dispose();
        }
        base.Dispose(disposing);
    }

    #region Windows Form Designer generated code

    /// <summary>
    ///  Required method for Designer support - do not modify
    ///  the contents of this method with the code editor.
    /// </summary>
    private void InitializeComponent()
    {
        components = new Container();
        txtBaseUrl = new TextBox();
        txtOtpauth = new TextBox();
        txtTotp = new TextBox();
        txtLog = new TextBox();
        btnRunFlow = new Button();
        btnRegister = new Button();
        btnConfirmEmail = new Button();
        btnLoginPwd = new Button();
        btnSetupMfa = new Button();
        btnLogout = new Button();
        btnLoginMfa = new Button();
        btnConfirmMfa = new Button();
        btnMe = new Button();
        btnRegenChallenge = new Button();
        btnPasswordReset = new Button();
        lblBaseUrl = new Label();
        lblOtpauth = new Label();
        lblTotp = new Label();
        SuspendLayout();
        // 
        // txtBaseUrl
        // 
        txtBaseUrl.Location = new System.Drawing.Point(12, 25);
        txtBaseUrl.Name = "txtBaseUrl";
        txtBaseUrl.Size = new System.Drawing.Size(360, 23);
        txtBaseUrl.TabIndex = 0;
        txtBaseUrl.Text = "https://localhost:52899";
        // 
        // txtOtpauth
        // 
        txtOtpauth.Location = new System.Drawing.Point(12, 78);
        txtOtpauth.Multiline = true;
        txtOtpauth.Name = "txtOtpauth";
        txtOtpauth.ReadOnly = true;
        txtOtpauth.ScrollBars = ScrollBars.Vertical;
        txtOtpauth.Size = new System.Drawing.Size(360, 60);
        txtOtpauth.TabIndex = 1;
        // 
        // txtTotp
        // 
        txtTotp.Location = new System.Drawing.Point(12, 159);
        txtTotp.Name = "txtTotp";
        txtTotp.Size = new System.Drawing.Size(180, 23);
        txtTotp.TabIndex = 2;
        // 
        // txtLog
        // 
        txtLog.Location = new System.Drawing.Point(12, 216);
        txtLog.Multiline = true;
        txtLog.Name = "txtLog";
        txtLog.ReadOnly = true;
        txtLog.ScrollBars = ScrollBars.Vertical;
        txtLog.Size = new System.Drawing.Size(660, 180);
        txtLog.TabIndex = 4;
        // 
        // btnRunFlow
        // 
        btnRunFlow.Location = new System.Drawing.Point(552, 157);
        btnRunFlow.Name = "btnRunFlow";
        btnRunFlow.Size = new System.Drawing.Size(120, 27);
        btnRunFlow.TabIndex = 3;
        btnRunFlow.Text = "Flow completo";
        btnRunFlow.UseVisualStyleBackColor = true;
        btnRunFlow.Click += btnRunFlow_Click;
        // 
        // btnRegister
        // 
        btnRegister.Location = new System.Drawing.Point(390, 25);
        btnRegister.Name = "btnRegister";
        btnRegister.Size = new System.Drawing.Size(120, 23);
        btnRegister.TabIndex = 5;
        btnRegister.Text = "1) Registra";
        btnRegister.UseVisualStyleBackColor = true;
        btnRegister.Click += btnRegister_Click;
        // 
        // btnConfirmEmail
        // 
        btnConfirmEmail.Location = new System.Drawing.Point(516, 25);
        btnConfirmEmail.Name = "btnConfirmEmail";
        btnConfirmEmail.Size = new System.Drawing.Size(120, 23);
        btnConfirmEmail.TabIndex = 6;
        btnConfirmEmail.Text = "2) Conferma email";
        btnConfirmEmail.UseVisualStyleBackColor = true;
        btnConfirmEmail.Click += btnConfirmEmail_Click;
        // 
        // btnLoginPwd
        // 
        btnLoginPwd.Location = new System.Drawing.Point(642, 25);
        btnLoginPwd.Name = "btnLoginPwd";
        btnLoginPwd.Size = new System.Drawing.Size(120, 23);
        btnLoginPwd.TabIndex = 7;
        btnLoginPwd.Text = "3) Login pwd";
        btnLoginPwd.UseVisualStyleBackColor = true;
        btnLoginPwd.Click += btnLoginPwd_Click;
        // 
        // btnSetupMfa
        // 
        btnSetupMfa.Location = new System.Drawing.Point(390, 54);
        btnSetupMfa.Name = "btnSetupMfa";
        btnSetupMfa.Size = new System.Drawing.Size(120, 23);
        btnSetupMfa.TabIndex = 8;
        btnSetupMfa.Text = "4) Setup MFA";
        btnSetupMfa.UseVisualStyleBackColor = true;
        btnSetupMfa.Click += btnSetupMfa_Click;
        // 
        // btnLogout
        // 
        btnLogout.Location = new System.Drawing.Point(516, 54);
        btnLogout.Name = "btnLogout";
        btnLogout.Size = new System.Drawing.Size(120, 23);
        btnLogout.TabIndex = 9;
        btnLogout.Text = "5) Logout";
        btnLogout.UseVisualStyleBackColor = true;
        btnLogout.Click += btnLogout_Click;
        // 
        // btnLoginMfa
        // 
        btnLoginMfa.Location = new System.Drawing.Point(642, 54);
        btnLoginMfa.Name = "btnLoginMfa";
        btnLoginMfa.Size = new System.Drawing.Size(120, 23);
        btnLoginMfa.TabIndex = 10;
        btnLoginMfa.Text = "6) Login MFA";
        btnLoginMfa.UseVisualStyleBackColor = true;
        btnLoginMfa.Click += btnLoginMfa_Click;
        // 
        // btnConfirmMfa
        // 
        btnConfirmMfa.Location = new System.Drawing.Point(198, 157);
        btnConfirmMfa.Name = "btnConfirmMfa";
        btnConfirmMfa.Size = new System.Drawing.Size(156, 27);
        btnConfirmMfa.TabIndex = 12;
        btnConfirmMfa.Text = "7) Conferma MFA";
        btnConfirmMfa.UseVisualStyleBackColor = true;
        btnConfirmMfa.Click += btnConfirmMfa_Click;
        // 
        // btnMe
        // 
        btnMe.Location = new System.Drawing.Point(390, 83);
        btnMe.Name = "btnMe";
        btnMe.Size = new System.Drawing.Size(120, 23);
        btnMe.TabIndex = 11;
        btnMe.Text = "8) /me";
        btnMe.UseVisualStyleBackColor = true;
        btnMe.Click += btnMe_Click;
        // 
        // btnRegenChallenge
        // 
        btnRegenChallenge.Location = new System.Drawing.Point(642, 83);
        btnRegenChallenge.Name = "btnRegenChallenge";
        btnRegenChallenge.Size = new System.Drawing.Size(120, 23);
        btnRegenChallenge.TabIndex = 16;
        btnRegenChallenge.Text = "9) Nuova challenge";
        btnRegenChallenge.UseVisualStyleBackColor = true;
        btnRegenChallenge.Click += btnRegenChallenge_Click;
        // 
        // btnPasswordReset
        // 
        btnPasswordReset.Location = new System.Drawing.Point(642, 112);
        btnPasswordReset.Name = "btnPasswordReset";
        btnPasswordReset.Size = new System.Drawing.Size(120, 23);
        btnPasswordReset.TabIndex = 17;
        btnPasswordReset.Text = "Reset password";
        btnPasswordReset.UseVisualStyleBackColor = true;
        btnPasswordReset.Click += btnPasswordReset_Click;
        // 
        // lblBaseUrl
        // 
        lblBaseUrl.AutoSize = true;
        lblBaseUrl.Location = new System.Drawing.Point(12, 7);
        lblBaseUrl.Name = "lblBaseUrl";
        lblBaseUrl.Size = new System.Drawing.Size(48, 15);
        lblBaseUrl.TabIndex = 13;
        lblBaseUrl.Text = "BaseUrl";
        // 
        // lblOtpauth
        // 
        lblOtpauth.AutoSize = true;
        lblOtpauth.Location = new System.Drawing.Point(12, 60);
        lblOtpauth.Name = "lblOtpauth";
        lblOtpauth.Size = new System.Drawing.Size(151, 15);
        lblOtpauth.TabIndex = 14;
        lblOtpauth.Text = "otpauth (leggi/QR applicativo)";
        // 
        // lblTotp
        // 
        lblTotp.AutoSize = true;
        lblTotp.Location = new System.Drawing.Point(12, 141);
        lblTotp.Name = "lblTotp";
        lblTotp.Size = new System.Drawing.Size(82, 15);
        lblTotp.TabIndex = 15;
        lblTotp.Text = "Codice TOTP";
        // 
        // MainForm
        // 
        AutoScaleDimensions = new System.Drawing.SizeF(7F, 15F);
        AutoScaleMode = AutoScaleMode.Font;
        ClientSize = new System.Drawing.Size(774, 411);
        Controls.Add(btnPasswordReset);
        Controls.Add(btnRegenChallenge);
        Controls.Add(btnMe);
        Controls.Add(btnConfirmMfa);
        Controls.Add(btnLoginMfa);
        Controls.Add(btnLogout);
        Controls.Add(btnSetupMfa);
        Controls.Add(btnLoginPwd);
        Controls.Add(btnConfirmEmail);
        Controls.Add(btnRegister);
        Controls.Add(lblTotp);
        Controls.Add(lblOtpauth);
        Controls.Add(lblBaseUrl);
        Controls.Add(btnRunFlow);
        Controls.Add(txtLog);
        Controls.Add(txtTotp);
        Controls.Add(txtOtpauth);
        Controls.Add(txtBaseUrl);
        FormBorderStyle = FormBorderStyle.FixedSingle;
        MaximizeBox = false;
        MinimizeBox = false;
        Name = "MainForm";
        StartPosition = FormStartPosition.CenterScreen;
        Text = "WinFORM_AUTH_Client";
        ResumeLayout(false);
        PerformLayout();
    }

    #endregion
}
