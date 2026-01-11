namespace SecureAuthMinimalApi.Options;

/// <summary>
/// Configurazione per il throttling dei login.
/// </summary>
public sealed class LoginThrottleOptions
{
    /// <summary>
    /// Numero massimo di tentativi falliti prima del blocco temporaneo.
    /// </summary>
    public int? MaxFailures { get; set; }

    /// <summary>
    /// Minuti di blocco dopo aver superato i tentativi consentiti.
    /// </summary>
    public int? LockMinutes { get; set; }
}
