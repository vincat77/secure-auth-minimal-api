using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Windows.Forms;

namespace WinFormsClient.Controls;

/// <summary>
/// Visualizza in chiaro il payload dell'id_token per debug/dev.
/// </summary>
public sealed partial class IdTokenViewerControl : UserControl
{
  public IdTokenViewerControl()
  {
    InitializeComponent();
  }

  public void SetToken(string? idToken)
  {
    if (string.IsNullOrWhiteSpace(idToken))
    {
      _payloadBox.Text = "Nessun id_token.";
      return;
    }

    try
    {
      var handler = new JwtSecurityTokenHandler { MapInboundClaims = false };
      var jwt = handler.ReadJwtToken(idToken);
      var sb = new StringBuilder();
      sb.AppendLine($"iss: {jwt.Issuer}");
      sb.AppendLine($"aud: {string.Join(",", jwt.Audiences)}");
      sb.AppendLine($"exp: {jwt.ValidTo:O}");
      foreach (var c in jwt.Claims)
      {
        sb.AppendLine($"{c.Type}: {c.Value}");
      }
      _payloadBox.Text = sb.ToString();
    }
    catch (Exception ex)
    {
      _payloadBox.Text = $"id_token non decodificato: {ex.Message}";
    }
  }
}
