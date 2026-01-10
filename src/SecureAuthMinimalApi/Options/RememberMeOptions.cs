namespace SecureAuthMinimalApi.Options;

/// <summary>
/// Configurazione cookie Refresh/RememberMe.
/// </summary>
public sealed class RememberMeOptions
{
    public int Days { get; set; } = 14;
    public string CookieName { get; set; } = "refresh_token";
    public string Path { get; set; } = "/refresh";
    public string SameSite { get; set; } = "Strict";
    public bool AllowSameSiteNone { get; set; }
    public bool RequireSecure { get; set; } = true;
}
