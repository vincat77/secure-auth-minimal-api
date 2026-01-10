namespace SecureAuthMinimalApi.Options;

/// <summary>
/// Opzioni per la generazione degli id_token (OpenID Connect-like).
/// </summary>
public sealed class IdTokenOptions
{
    public string? Issuer { get; set; }
    public string? Audience { get; set; }
    public string? Secret { get; set; }
    public string? SigningKeyPath { get; set; }
    public int Minutes { get; set; } = 30;
}
