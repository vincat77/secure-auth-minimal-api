namespace SecureAuthMinimalApi.Services;

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
}
