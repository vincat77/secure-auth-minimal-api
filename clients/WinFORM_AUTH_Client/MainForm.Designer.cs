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
    private Label lblBaseUrl = null!;
    private Label lblOtpauth = null!;
    private Label lblTotp = null!;

    /// <summary>
    ///  Clean up any resources being used.
    /// </summary>
    /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
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
        txtTotp.Size = new System.Drawing.Size(200, 23);
        txtTotp.TabIndex = 2;
        // 
        // txtLog
        // 
        txtLog.Location = new System.Drawing.Point(12, 216);
        txtLog.Multiline = true;
        txtLog.Name = "txtLog";
        txtLog.ReadOnly = true;
        txtLog.ScrollBars = ScrollBars.Vertical;
        txtLog.Size = new System.Drawing.Size(360, 180);
        txtLog.TabIndex = 4;
        // 
        // btnRunFlow
        // 
        btnRunFlow.Location = new System.Drawing.Point(240, 157);
        btnRunFlow.Name = "btnRunFlow";
        btnRunFlow.Size = new System.Drawing.Size(132, 27);
        btnRunFlow.TabIndex = 3;
        btnRunFlow.Text = "Esegui flow MFA";
        btnRunFlow.UseVisualStyleBackColor = true;
        btnRunFlow.Click += btnRunFlow_Click;
        // 
        // lblBaseUrl
        // 
        lblBaseUrl.AutoSize = true;
        lblBaseUrl.Location = new System.Drawing.Point(12, 7);
        lblBaseUrl.Name = "lblBaseUrl";
        lblBaseUrl.Size = new System.Drawing.Size(48, 15);
        lblBaseUrl.TabIndex = 5;
        lblBaseUrl.Text = "BaseUrl";
        // 
        // lblOtpauth
        // 
        lblOtpauth.AutoSize = true;
        lblOtpauth.Location = new System.Drawing.Point(12, 60);
        lblOtpauth.Name = "lblOtpauth";
        lblOtpauth.Size = new System.Drawing.Size(151, 15);
        lblOtpauth.TabIndex = 6;
        lblOtpauth.Text = "otpauth (leggi/QR applicativo)";
        // 
        // lblTotp
        // 
        lblTotp.AutoSize = true;
        lblTotp.Location = new System.Drawing.Point(12, 141);
        lblTotp.Name = "lblTotp";
        lblTotp.Size = new System.Drawing.Size(82, 15);
        lblTotp.TabIndex = 7;
        lblTotp.Text = "Codice TOTP";
        // 
        // MainForm
        // 
        AutoScaleDimensions = new System.Drawing.SizeF(7F, 15F);
        AutoScaleMode = AutoScaleMode.Font;
        ClientSize = new System.Drawing.Size(384, 411);
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
