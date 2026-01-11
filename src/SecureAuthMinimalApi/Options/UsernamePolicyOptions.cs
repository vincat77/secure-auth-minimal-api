namespace SecureAuthMinimalApi.Options;

/// <summary>
/// Configurazione per la normalizzazione dello username.
/// </summary>
public sealed class UsernamePolicyOptions
{
    /// <summary>
    /// Se true forza lo username in lowercase durante login/registrazione.
    /// </summary>
    public bool Lowercase { get; set; }
}
