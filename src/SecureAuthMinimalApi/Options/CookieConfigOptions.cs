namespace SecureAuthMinimalApi.Options;

/// <summary>
/// Opzioni generali per i cookie (flag Secure/SameSite/Path) da applicare come default.
/// </summary>
public sealed class CookieConfigOptions
{
    /// <summary>
    /// Richiede il flag Secure sui cookie (default true).
    /// </summary>
    public bool RequireSecure { get; set; } = true;

    /// <summary>
    /// SameSite predefinito (Strict/Lax/None). Se null usa default del framework.
    /// </summary>
    public string? SameSite { get; set; }

    /// <summary>
    /// Path predefinito per i cookie (se applicabile).
    /// </summary>
    public string? Path { get; set; }

    /// <summary>
    /// Permette SameSite=None (default false, in prod sconsigliato).
    /// </summary>
    public bool AllowSameSiteNone { get; set; }
}
