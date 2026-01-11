namespace SecureAuthMinimalApi.Utilities;

/// <summary>
/// Utility per la gestione di opzioni cookie (SameSite/Secure).
/// </summary>
public static class CookieUtils
{
    /// <summary>
    /// Interpreta la stringa SameSite con fallback e blocchi di sicurezza per ambienti non Development.
    /// </summary>
    public static SameSiteMode ParseSameSite(string? value, bool allowNone, bool isDevelopment, ILogger logger, string context)
    {
        var sameSiteString = string.IsNullOrWhiteSpace(value) ? "Strict" : value;
        var sameSite = SameSiteMode.Strict;
        if (sameSiteString.Equals("Lax", StringComparison.OrdinalIgnoreCase))
            sameSite = SameSiteMode.Lax;
        else if (sameSiteString.Equals("None", StringComparison.OrdinalIgnoreCase))
            sameSite = SameSiteMode.None;
        else if (!sameSiteString.Equals("Strict", StringComparison.OrdinalIgnoreCase))
            logger.LogWarning("{Context}:SameSite non valido ({SameSite}), fallback a Strict", context, sameSiteString);

        if (!isDevelopment && sameSite == SameSiteMode.None && !allowNone)
        {
            logger.LogWarning("{Context}:SameSite=None in ambiente non Development non consentito: forzato a Strict (abilita {Context}:AllowSameSiteNone per override esplicito)", context, sameSiteString);
            sameSite = SameSiteMode.Strict;
        }

        return sameSite;
    }
}
