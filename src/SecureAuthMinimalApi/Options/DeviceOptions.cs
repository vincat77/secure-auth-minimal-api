namespace SecureAuthMinimalApi.Options;

/// <summary>
/// Configurazione per il device cookie legato ai refresh token.
/// </summary>
public sealed class DeviceOptions
{
    public string CookieName { get; set; } = "device_id";
    public string SameSite { get; set; } = "Strict";
    public bool AllowSameSiteNone { get; set; }
    public bool RequireSecure { get; set; } = true;
    public int PersistDays { get; set; } = 90;
    public bool ClearOnLogoutAll { get; set; }
}
