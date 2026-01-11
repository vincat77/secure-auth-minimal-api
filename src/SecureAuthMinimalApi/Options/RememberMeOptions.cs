namespace SecureAuthMinimalApi.Options;

/// <summary>
/// Configurazione cookie Refresh/RememberMe.
/// </summary>
public sealed class RememberMeOptions
{
    /// <summary>
    /// Durata del refresh/remember in giorni.
    /// </summary>
    public int Days { get; set; } = 14;
    /// <summary>
    /// Nome del cookie refresh/remember.
    /// </summary>
    public string CookieName { get; set; } = "refresh_token";
    /// <summary>
    /// Path del cookie refresh.
    /// </summary>
    public string Path { get; set; } = "/refresh";
    /// <summary>
    /// SameSite del cookie refresh (Strict/Lax/None).
    /// </summary>
    public string SameSite { get; set; } = "Strict";
    /// <summary>
    /// Permette SameSite=None (default false; in prod sconsigliato).
    /// </summary>
    public bool AllowSameSiteNone { get; set; }
    /// <summary>
    /// Flag Secure per il cookie refresh (default true).
    /// </summary>
    public bool RequireSecure { get; set; } = true;
}
