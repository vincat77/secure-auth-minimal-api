namespace SecureAuthMinimalApi.Options;

/// <summary>
/// Configurazione per il device cookie legato ai refresh token.
/// </summary>
public sealed class DeviceOptions
{
    /// <summary>
    /// Nome del cookie device-id (Device:CookieName).
    /// </summary>
    public string CookieName { get; set; } = "device_id";
    /// <summary>
    /// SameSite per il cookie device (Strict/Lax/None).
    /// </summary>
    public string SameSite { get; set; } = "Strict";
    /// <summary>
    /// Permette SameSite=None (default false; in prod sconsigliato).
    /// </summary>
    public bool AllowSameSiteNone { get; set; }
    /// <summary>
    /// Flag Secure per il cookie device (default true).
    /// </summary>
    public bool RequireSecure { get; set; } = true;
    /// <summary>
    /// Durata del cookie device in giorni.
    /// </summary>
    public int PersistDays { get; set; } = 90;
    /// <summary>
    /// Se true cancella il device cookie su logout-all.
    /// </summary>
    public bool ClearOnLogoutAll { get; set; }
}
