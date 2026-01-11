namespace SecureAuthMinimalApi.Options;

/// <summary>
/// Opzioni per la gestione delle sessioni (idle timeout, ecc.).
/// </summary>
public sealed class SessionConfigOptions
{
    /// <summary>
    /// Timeout di inattività in minuti. <=0 per disabilitare idle timeout.
    /// </summary>
    public int IdleMinutes { get; set; } = 0;
}
