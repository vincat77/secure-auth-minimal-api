namespace SecureAuthMinimalApi.Options;

/// <summary>
/// Opzioni per la generazione e validazione dei JWT di accesso.
/// </summary>
public sealed class JwtOptions
{
    /// <summary>
    /// Issuer dei JWT (Jwt:Issuer).
    /// </summary>
    public string Issuer { get; set; } = "";
    /// <summary>
    /// Audience dei JWT (Jwt:Audience).
    /// </summary>
    public string Audience { get; set; } = "";
    /// <summary>
    /// Chiave simmetrica HMAC (>=32 caratteri) per firma/validazione (Jwt:SecretKey).
    /// </summary>
    public string SecretKey { get; set; } = "";
    /// <summary>
    /// Durata del token di accesso in minuti.
    /// </summary>
    public int AccessTokenMinutes { get; set; } = 30;
}
