namespace SecureAuthMinimalApi.Options;

/// <summary>
/// Opzioni per la generazione degli id_token (OpenID Connect-like).
/// </summary>
public sealed class IdTokenOptions
{
    /// <summary>
    /// Issuer per l'id_token (IdToken:Issuer).
    /// </summary>
    public string? Issuer { get; set; }
    /// <summary>
    /// Audience per l'id_token (IdToken:Audience).
    /// </summary>
    public string? Audience { get; set; }
    /// <summary>
    /// Chiave HMAC di fallback (solo Dev) se non viene fornita la chiave di firma.
    /// </summary>
    public string? Secret { get; set; }
    /// <summary>
    /// Percorso della chiave di firma RSA/EC (PEM/XML) per l'id_token.
    /// </summary>
    public string? SigningKeyPath { get; set; }
    /// <summary>
    /// Durata dell'id_token in minuti.
    /// </summary>
    public int Minutes { get; set; } = 30;
}
