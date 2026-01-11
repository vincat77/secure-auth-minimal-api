namespace SecureAuthMinimalApi.Options;

/// <summary>
/// Opzioni per l'HMAC dei token (pepper lato server).
/// </summary>
public sealed class TokenHashingOptions
{
    /// <summary>
    /// Pepper usato per l'HMAC dei token di conferma email (stringa lunga, segreta per ambiente).
    /// </summary>
    public string EmailConfirmPepper { get; set; } = "dev-email-pepper";
}
