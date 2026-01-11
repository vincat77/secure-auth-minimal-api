namespace SecureAuthMinimalApi.Options;

/// <summary>
/// Opzioni di policy password configurabili via appsettings.
/// </summary>
public sealed class PasswordPolicyOptions
{
    /// <summary>
    /// Lunghezza minima password (consigliato >=12).
    /// </summary>
    public int MinLength { get; set; } = 12;

    /// <summary>
    /// Ritorna MinLength normalizzato (almeno 12).
    /// </summary>
    public int EffectiveMinLength => MinLength < 1 ? 12 : MinLength;
    /// <summary>
    /// Richiede almeno una maiuscola.
    /// </summary>
    public bool RequireUpper { get; set; }
    /// <summary>
    /// Richiede almeno una minuscola.
    /// </summary>
    public bool RequireLower { get; set; }
    /// <summary>
    /// Richiede almeno una cifra.
    /// </summary>
    public bool RequireDigit { get; set; }
    /// <summary>
    /// Richiede almeno un simbolo.
    /// </summary>
    public bool RequireSymbol { get; set; }
}
