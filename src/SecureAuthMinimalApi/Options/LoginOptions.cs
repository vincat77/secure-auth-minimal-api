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

    /// <summary>
    /// Numero massimo di richieste di login consentite nella finestra di rate limit.
    /// </summary>
    public int RateLimitRequests { get; set; } = 0;

    /// <summary>
    /// Durata della finestra di rate limit (in minuti) per il login.
    /// </summary>
    public int RateLimitWindowMinutes { get; set; } = 1;
}

/// <summary>
/// Opzioni di rate limit per la registrazione.
/// </summary>
public sealed class RegisterRateLimitOptions
{
    /// <summary>Numero massimo di richieste di registrazione nella finestra.</summary>
    public int Requests { get; set; } = 0;

    /// <summary>Finestra di rate limit (minuti).</summary>
    public int WindowMinutes { get; set; } = 1;
}

/// <summary>
/// Opzioni di rate limit per l'endpoint /confirm-email.
/// </summary>
public sealed class ConfirmEmailRateLimitOptions
{
    /// <summary>Numero massimo di richieste di conferma nella finestra.</summary>
    public int Requests { get; set; } = 0;

    /// <summary>Durata della finestra (minuti).</summary>
    public int WindowMinutes { get; set; } = 1;
}

/// <summary>
/// Opzioni di rate limit per l'endpoint /refresh.
/// </summary>
public sealed class RefreshRateLimitOptions
{
    /// <summary>Numero massimo di richieste di refresh nella finestra.</summary>
    public int Requests { get; set; } = 0;

    /// <summary>Durata della finestra (minuti).</summary>
    public int WindowMinutes { get; set; } = 1;
}

/// <summary>
/// Opzioni di rate limit per la conferma MFA (/login/confirm-mfa).
/// </summary>
public sealed class ConfirmMfaRateLimitOptions
{
    /// <summary>Numero massimo di richieste nella finestra.</summary>
    public int Requests { get; set; } = 0;

    /// <summary>Durata della finestra (minuti).</summary>
    public int WindowMinutes { get; set; } = 1;
}
