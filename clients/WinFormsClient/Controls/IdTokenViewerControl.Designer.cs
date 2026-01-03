namespace WinFormsClient.Controls;

partial class IdTokenViewerControl
{
  /// <summary>Required designer variable.</summary>
  private System.ComponentModel.IContainer components = null!;

  private Label _titleLabel = null!;
  private TextBox _payloadBox = null!;

  /// <summary>Clean up any resources being used.</summary>
  protected override void Dispose(bool disposing)
  {
    if (disposing)
    {
      components?.Dispose();
    }
    base.Dispose(disposing);
  }

  #region Component Designer generated code

  /// <summary>Required method for Designer support - do not modify
  /// the contents of this method with the code editor.</summary>
  private void InitializeComponent()
  {
    components = new System.ComponentModel.Container();
    _titleLabel = new Label();
    _payloadBox = new TextBox();
    SuspendLayout();
    // 
    // _titleLabel
    // 
    _titleLabel.AutoSize = true;
    _titleLabel.Location = new Point(0, 0);
    _titleLabel.Name = "_titleLabel";
    _titleLabel.Size = new Size(119, 15);
    _titleLabel.TabIndex = 0;
    _titleLabel.Text = "id_token (solo dev):";
    // 
    // _payloadBox
    // 
    _payloadBox.Location = new Point(0, 20);
    _payloadBox.Multiline = true;
    _payloadBox.Name = "_payloadBox";
    _payloadBox.ReadOnly = true;
    _payloadBox.ScrollBars = ScrollBars.Vertical;
    _payloadBox.Size = new Size(360, 140);
    _payloadBox.TabIndex = 1;
    // 
    // IdTokenViewerControl
    // 
    AutoScaleDimensions = new SizeF(7F, 15F);
    AutoScaleMode = AutoScaleMode.Font;
    BorderStyle = BorderStyle.FixedSingle;
    Controls.Add(_payloadBox);
    Controls.Add(_titleLabel);
    Name = "IdTokenViewerControl";
    Size = new Size(362, 163);
    ResumeLayout(false);
    PerformLayout();
  }

  #endregion
}
