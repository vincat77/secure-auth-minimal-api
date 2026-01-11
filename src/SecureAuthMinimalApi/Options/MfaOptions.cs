namespace SecureAuthMinimalApi.Options;

/// <summary>
/// Configurazione per le challenge MFA TOTP.
/// </summary>
public sealed class MfaOptions
{
    /// <summary>
    /// Durata in minuti della challenge MFA prima di scadere.
    /// </summary>
    public int ChallengeMinutes { get; set; } = 10;

    /// <summary>
    /// Se true richiede che l'user-agent della conferma MFA corrisponda a quello del login.
    /// </summary>
    public bool RequireUaMatch { get; set; } = true;

    /// <summary>
    /// Se true richiede che l'IP della conferma MFA corrisponda a quello del login.
    /// </summary>
    public bool RequireIpMatch { get; set; } = false;

    /// <summary>
    /// Numero massimo di tentativi consentiti per ciascuna challenge MFA.
    /// </summary>
    public int MaxAttemptsPerChallenge { get; set; } = 5;
}
