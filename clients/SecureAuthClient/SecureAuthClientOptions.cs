namespace SecureAuthClient;

/// <summary>
/// Opzioni per configurare il client API.
/// </summary>
public sealed class SecureAuthClientOptions
{
    /// <summary>
    /// Base URL dell'API, ad esempio https://localhost:52899.
    /// </summary>
    public required string BaseUrl { get; init; }

    /// <summary>
    /// User-Agent da inviare (utile se il server richiede match UA).
    /// </summary>
    public string UserAgent { get; init; } = "SecureAuthClient/1.0";

    /// <summary>
    /// Timeout per le richieste HTTP.
    /// </summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(30);
}
