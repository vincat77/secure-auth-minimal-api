using System.ComponentModel;
using System.Drawing;
using System.Windows.Forms;
using WinFormsClient.Controls;

namespace WinFormsClient;

public partial class MainForm
{
    private IContainer components = null!;
    private StatusBanner _banner = null!;
    private Panel _rootPanel = null!;
    private LabeledTextBoxControl _urlControl = null!;
    private LabeledTextBoxControl _userInput = null!;
    private LabeledTextBoxControl _emailInput = null!;
    private LabeledTextBoxControl _nameInput = null!;
    private LabeledTextBoxControl _givenNameInput = null!;
    private LabeledTextBoxControl _familyNameInput = null!;
    private LabeledTextBoxControl _pictureInput = null!;
    private LabeledTextBoxControl _passwordControl = null!;
    private LabeledTextBoxControl _currentPasswordInput = null!;
    private LabeledTextBoxControl _newPasswordInput = null!;
    private LabeledTextBoxControl _confirmPasswordInput = null!;
    private ActionButtonsControl _actions = null!;
    private MfaPanelControl _mfaPanel = null!;
    private LabeledTextBoxControl _confirmTokenInput = null!;
    private StatusInfoControl _statusInfo = null!;
    private SessionCard _sessionCard = null!;
    private DeviceInfoControl _deviceInfo = null!;
    private DeviceAlertControl _deviceAlert = null!;
    private IdTokenViewerControl _idTokenViewer = null!;
    private Label _busyLabel = null!;
    private LogPanelControl _logPanel = null!;
    private System.Windows.Forms.Timer _countdownTimer = null!;

  private void InitializeComponent()
  {
    components = new Container();
    _banner = new StatusBanner();
    _rootPanel = new Panel();
    _urlControl = new LabeledTextBoxControl();
    _userInput = new LabeledTextBoxControl();
    _emailInput = new LabeledTextBoxControl();
    _nameInput = new LabeledTextBoxControl();
    _givenNameInput = new LabeledTextBoxControl();
    _familyNameInput = new LabeledTextBoxControl();
    _pictureInput = new LabeledTextBoxControl();
    _passwordControl = new LabeledTextBoxControl();
    _currentPasswordInput = new LabeledTextBoxControl();
    _newPasswordInput = new LabeledTextBoxControl();
    _confirmPasswordInput = new LabeledTextBoxControl();
    _actions = new ActionButtonsControl();
    _mfaPanel = new MfaPanelControl();
    _confirmTokenInput = new LabeledTextBoxControl();
    _statusInfo = new StatusInfoControl();
    _sessionCard = new SessionCard();
    _deviceInfo = new DeviceInfoControl();
    _deviceAlert = new DeviceAlertControl();
    _idTokenViewer = new IdTokenViewerControl();
    _busyLabel = new Label();
    _logPanel = new LogPanelControl();
    _countdownTimer = new System.Windows.Forms.Timer(components);
    _rootPanel.SuspendLayout();
    SuspendLayout();
    // 
    // _banner
    // 
    _banner.Dock = DockStyle.Top;
    _banner.Location = new Point(0, 0);
    _banner.Name = "_banner";
    _banner.Size = new Size(1320, 30);
    _banner.TabIndex = 0;
    // 
    // _rootPanel
    // 
    _rootPanel.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
    _rootPanel.AutoScroll = true;
    _rootPanel.Controls.Add(_urlControl);
    _rootPanel.Controls.Add(_userInput);
    _rootPanel.Controls.Add(_emailInput);
    _rootPanel.Controls.Add(_nameInput);
    _rootPanel.Controls.Add(_givenNameInput);
    _rootPanel.Controls.Add(_familyNameInput);
    _rootPanel.Controls.Add(_pictureInput);
    _rootPanel.Controls.Add(_passwordControl);
    _rootPanel.Controls.Add(_currentPasswordInput);
    _rootPanel.Controls.Add(_newPasswordInput);
    _rootPanel.Controls.Add(_confirmPasswordInput);
    _rootPanel.Controls.Add(_actions);
    _rootPanel.Controls.Add(_mfaPanel);
    _rootPanel.Controls.Add(_confirmTokenInput);
    _rootPanel.Controls.Add(_statusInfo);
    _rootPanel.Controls.Add(_sessionCard);
    _rootPanel.Controls.Add(_deviceInfo);
    _rootPanel.Controls.Add(_deviceAlert);
    _rootPanel.Controls.Add(_idTokenViewer);
    _rootPanel.Controls.Add(_busyLabel);
    _rootPanel.Controls.Add(_logPanel);
    _rootPanel.Location = new Point(0, 30);
    _rootPanel.Name = "_rootPanel";
    _rootPanel.Size = new Size(1280, 840);
    _rootPanel.TabIndex = 1;
    // 
    // _urlControl
    // 
    _urlControl.LabelText = "Base URL:";
    _urlControl.Location = new Point(16, 16);
    _urlControl.Name = "_urlControl";
    _urlControl.Size = new Size(330, 30);
    _urlControl.TabIndex = 0;
    _urlControl.UseSystemPasswordChar = false;
    _urlControl.ValueText = "https://localhost:52899";
    // 
    // _userInput
    // 
    _userInput.LabelText = "Username:";
    _userInput.Location = new Point(16, 56);
    _userInput.Name = "_userInput";
    _userInput.Size = new Size(330, 30);
    _userInput.TabIndex = 1;
    _userInput.UseSystemPasswordChar = false;
    _userInput.ValueText = "demo";
    // 
    // _emailInput
    // 
    _emailInput.LabelText = "Email:";
    _emailInput.Location = new Point(16, 96);
    _emailInput.Name = "_emailInput";
    _emailInput.Size = new Size(330, 30);
    _emailInput.TabIndex = 2;
    _emailInput.UseSystemPasswordChar = false;
    _emailInput.ValueText = "demo@example.com";
    // 
    // _nameInput
    // 
    _nameInput.LabelText = "Nome completo:";
    _nameInput.Location = new Point(16, 136);
    _nameInput.Name = "_nameInput";
    _nameInput.Size = new Size(330, 30);
    _nameInput.TabIndex = 3;
    _nameInput.UseSystemPasswordChar = false;
    _nameInput.ValueText = "Demo User";
    // 
    // _givenNameInput
    // 
    _givenNameInput.LabelText = "Nome:";
    _givenNameInput.Location = new Point(16, 176);
    _givenNameInput.Name = "_givenNameInput";
    _givenNameInput.Size = new Size(330, 30);
    _givenNameInput.TabIndex = 4;
    _givenNameInput.UseSystemPasswordChar = false;
    _givenNameInput.ValueText = "Demo";
    // 
    // _familyNameInput
    // 
    _familyNameInput.LabelText = "Cognome:";
    _familyNameInput.Location = new Point(16, 216);
    _familyNameInput.Name = "_familyNameInput";
    _familyNameInput.Size = new Size(330, 30);
    _familyNameInput.TabIndex = 5;
    _familyNameInput.UseSystemPasswordChar = false;
    _familyNameInput.ValueText = "User";
    // 
    // _pictureInput
    // 
    _pictureInput.LabelText = "Avatar URL (picture):";
    _pictureInput.Location = new Point(16, 256);
    _pictureInput.Name = "_pictureInput";
    _pictureInput.Size = new Size(330, 30);
    _pictureInput.TabIndex = 6;
    _pictureInput.UseSystemPasswordChar = false;
    _pictureInput.ValueText = "https://api.dicebear.com/9.x/adventurer/svg?seed=Mason";
    // 
    // _passwordControl
    // 
    _passwordControl.LabelText = "Password:";
    _passwordControl.Location = new Point(16, 296);
    _passwordControl.Name = "_passwordControl";
    _passwordControl.Size = new Size(330, 30);
    _passwordControl.TabIndex = 7;
    _passwordControl.UseSystemPasswordChar = true;
    _passwordControl.ValueText = "123456789012";
    // 
    // _currentPasswordInput
    // 
    _currentPasswordInput.LabelText = "Password corrente:";
    _currentPasswordInput.Location = new Point(184, 690);
    _currentPasswordInput.Name = "_currentPasswordInput";
    _currentPasswordInput.Size = new Size(330, 30);
    _currentPasswordInput.TabIndex = 13;
    _currentPasswordInput.UseSystemPasswordChar = true;
    _currentPasswordInput.ValueText = "";
    // 
    // _newPasswordInput
    // 
    _newPasswordInput.LabelText = "Nuova password:";
    _newPasswordInput.Location = new Point(184, 730);
    _newPasswordInput.Name = "_newPasswordInput";
    _newPasswordInput.Size = new Size(330, 30);
    _newPasswordInput.TabIndex = 14;
    _newPasswordInput.UseSystemPasswordChar = true;
    _newPasswordInput.ValueText = "";
    // 
    // _confirmPasswordInput
    // 
    _confirmPasswordInput.LabelText = "Conferma password:";
    _confirmPasswordInput.Location = new Point(184, 770);
    _confirmPasswordInput.Name = "_confirmPasswordInput";
    _confirmPasswordInput.Size = new Size(330, 30);
    _confirmPasswordInput.TabIndex = 15;
    _confirmPasswordInput.UseSystemPasswordChar = true;
    _confirmPasswordInput.ValueText = "";
    // 
    // _actions
    // 
    _actions.BorderStyle = BorderStyle.FixedSingle;
    _actions.Location = new Point(16, 336);
    _actions.Name = "_actions";
    _actions.RememberChecked = false;
    _actions.Size = new Size(162, 464);
    _actions.TabIndex = 8;
    // 
    // _mfaPanel
    // 
    _mfaPanel.ChallengeId = "";
    _mfaPanel.Location = new Point(858, 202);
    _mfaPanel.Name = "_mfaPanel";
    _mfaPanel.Size = new Size(380, 260);
    _mfaPanel.TabIndex = 5;
    _mfaPanel.TotpCode = "";
    // 
    // _confirmTokenInput
    // 
    _confirmTokenInput.LabelText = "Token conferma email:";
    _confirmTokenInput.Location = new Point(512, 166);
    _confirmTokenInput.Name = "_confirmTokenInput";
    _confirmTokenInput.Size = new Size(340, 30);
    _confirmTokenInput.TabIndex = 6;
    _confirmTokenInput.UseSystemPasswordChar = false;
    _confirmTokenInput.ValueText = "";
    // 
    // _statusInfo
    // 
    _statusInfo.Location = new Point(497, 202);
    _statusInfo.Name = "_statusInfo";
    _statusInfo.Size = new Size(340, 160);
    _statusInfo.TabIndex = 7;
    // 
    // _sessionCard
    // 
    _sessionCard.BackColor = Color.FromArgb(240, 248, 255);
    _sessionCard.BorderStyle = BorderStyle.FixedSingle;
    _sessionCard.Location = new Point(858, 6);
    _sessionCard.Name = "_sessionCard";
    _sessionCard.Padding = new Padding(8);
    _sessionCard.Size = new Size(340, 190);
    _sessionCard.TabIndex = 8;
    // 
    // _deviceInfo
    // 
    _deviceInfo.BackColor = Color.WhiteSmoke;
    _deviceInfo.BorderStyle = BorderStyle.FixedSingle;
    _deviceInfo.Location = new Point(512, 3);
    _deviceInfo.Name = "_deviceInfo";
    _deviceInfo.Padding = new Padding(8);
    _deviceInfo.Size = new Size(340, 90);
    _deviceInfo.TabIndex = 9;
    // 
    // _deviceAlert
    // 
    _deviceAlert.BackColor = Color.White;
    _deviceAlert.BorderStyle = BorderStyle.FixedSingle;
    _deviceAlert.Location = new Point(512, 96);
    _deviceAlert.Name = "_deviceAlert";
    _deviceAlert.Padding = new Padding(8);
    _deviceAlert.Size = new Size(340, 60);
    _deviceAlert.TabIndex = 10;
    // 
    // _idTokenViewer
    // 
    _idTokenViewer.BorderStyle = BorderStyle.FixedSingle;
    _idTokenViewer.Location = new Point(858, 472);
    _idTokenViewer.Name = "_idTokenViewer";
    _idTokenViewer.Size = new Size(362, 163);
    _idTokenViewer.TabIndex = 13;
    // 
    // _busyLabel
    // 
    _busyLabel.AutoSize = true;
    _busyLabel.ForeColor = Color.DarkSlateGray;
    _busyLabel.Location = new Point(392, 576);
    _busyLabel.Name = "_busyLabel";
    _busyLabel.Size = new Size(0, 15);
    _busyLabel.TabIndex = 11;
    // 
    // _logPanel
    // 
    _logPanel.Location = new Point(184, 352);
    _logPanel.Name = "_logPanel";
    _logPanel.Size = new Size(666, 322);
    _logPanel.TabIndex = 12;
    // 
    // _countdownTimer
    // 
    _countdownTimer.Interval = 1000;
    // 
    // MainForm
    // 
    AutoScaleDimensions = new SizeF(7F, 15F);
    AutoScaleMode = AutoScaleMode.Font;
    ClientSize = new Size(1320, 900);
    Controls.Add(_rootPanel);
    Controls.Add(_banner);
    Name = "MainForm";
    Text = "SecureAuth WinForms Client";
    _rootPanel.ResumeLayout(false);
    _rootPanel.PerformLayout();
    ResumeLayout(false);
  }
}
