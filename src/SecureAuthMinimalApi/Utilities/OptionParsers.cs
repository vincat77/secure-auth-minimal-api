namespace SecureAuthMinimalApi.Utilities;

/// <summary>
/// Helper per parsing sicuro di valori di configurazione.
/// </summary>
public static class OptionParsers
{
    public static bool ParseBool(string? raw, bool defaultValue, string key, ILogger logger)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return defaultValue;

        if (bool.TryParse(raw, out var parsed))
            return parsed;

        logger.LogWarning("{Key} non valido ({Value}), fallback a {Default}", key, raw, defaultValue);
        return defaultValue;
    }

    public static int ParseInt(string? raw, int defaultValue, int minValue, string key, ILogger logger)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return defaultValue;

        if (int.TryParse(raw, out var parsed) && parsed >= minValue)
            return parsed;

        logger.LogWarning("{Key} non valido ({Value}), fallback a {Default}", key, raw, defaultValue);
        return defaultValue;
    }
}
