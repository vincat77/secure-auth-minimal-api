namespace SecureAuthMinimalApi.Options;

/// <summary>
/// Opzioni per il binding e la sicurezza dei refresh token.
/// </summary>
public sealed class RefreshOptions
{
    /// <summary>
    /// Richiede match esatto dell'User-Agent tra richiesta di refresh e token salvato.
    /// Default false (binding principale via device cookie).
    /// </summary>
    public bool RequireUserAgentMatch { get; set; } = false;

    /// <summary>
    /// Cookie di refresh: nome, percorso, SameSite, AllowNone, Secure.
    /// </summary>
    public string CookieName { get; set; } = "refresh_token";
    public string Path { get; set; } = "/refresh";
    public string? SameSite { get; set; }
    public bool AllowSameSiteNone { get; set; }
    public bool RequireSecure { get; set; } = true;

    /// <summary>
    /// Chiave HMAC per hash dei refresh token (fallback a Jwt:SecretKey se vuota).
    /// </summary>
    public string? HmacKey { get; set; }
}
