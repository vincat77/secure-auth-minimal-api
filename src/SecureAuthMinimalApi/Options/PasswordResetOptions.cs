namespace SecureAuthMinimalApi.Options;

/// <summary>
/// Opzioni per il flusso di reset password (richiesta e conferma).
/// </summary>
public sealed class PasswordResetOptions
{
    /// <summary>
    /// Durata in minuti del token di reset prima della scadenza (default: 30).
    /// </summary>
    public int ExpirationMinutes { get; set; } = 30;

    /// <summary>
    /// Se true consente la richiesta solo a utenti con email confermata (default: true).
    /// </summary>
    public bool RequireConfirmed { get; set; } = true;

    /// <summary>
    /// In ambiente di sviluppo/test restituisce il token di reset nella response per facilitare gli automatismi (default: false).
    /// </summary>
    public bool IncludeTokenInResponseForTesting { get; set; } = false;

    /// <summary>
    /// Giorni di retention per token scaduti/usati prima che il cleanup li rimuova (default: 7).
    /// </summary>
    public int RetentionDays { get; set; } = 7;

    /// <summary>
    /// Numero massimo di richieste per finestra di rate limit su stessa email/IP (default: 5; 0 disabilita).
    /// </summary>
    public int RateLimitRequests { get; set; } = 5;

    /// <summary>
    /// Durata della finestra di rate limit in minuti (default: 15; 0 disabilita).
    /// </summary>
    public int RateLimitWindowMinutes { get; set; } = 15;
}
