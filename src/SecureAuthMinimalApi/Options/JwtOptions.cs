namespace SecureAuthMinimalApi.Options;

/// <summary>
/// Opzioni per la generazione e validazione dei JWT di accesso.
/// </summary>
public sealed class JwtOptions
{
    public string Issuer { get; set; } = "";
    public string Audience { get; set; } = "";
    public string SecretKey { get; set; } = "";
    public int AccessTokenMinutes { get; set; } = 30;
}
