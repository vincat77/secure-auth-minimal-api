namespace SecureAuthMinimalApi.Options;

/// <summary>
/// Opzioni per il login: normalizzazione username, requisito conferma email e MFA.
/// </summary>
public sealed class LoginOptions
{
    /// <summary>
    /// Se true forza lo username in lowercase in fase di login/registrazione.
    /// </summary>
    public bool ForceLowerUsername { get; set; }

    /// <summary>
    /// Se true il login richiede che l'email sia confermata.
    /// </summary>
    public bool EmailConfirmationRequired { get; set; } = true;

    /// <summary>
    /// Durata (minuti) della challenge MFA prima di scadere.
    /// </summary>
    public int MfaChallengeMinutes { get; set; } = 10;

    /// <summary>
    /// Richiede che l'user-agent della richiesta MFA matchi quello della login.
    /// </summary>
    public bool MfaRequireUaMatch { get; set; } = true;

    /// <summary>
    /// Richiede che l'IP della richiesta MFA matchi quello della login.
    /// </summary>
    public bool MfaRequireIpMatch { get; set; } = false;

    /// <summary>
    /// Numero massimo di tentativi per challenge MFA.
    /// </summary>
    public int MfaMaxAttempts { get; set; } = 5;
}
