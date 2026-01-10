namespace SecureAuthMinimalApi.Options;

/// <summary>
/// Opzioni di policy password configurabili via appsettings.
/// </summary>
public sealed class PasswordPolicyOptions
{
    public int MinLength { get; set; } = 12;
    public bool RequireUpper { get; set; }
    public bool RequireLower { get; set; }
    public bool RequireDigit { get; set; }
    public bool RequireSymbol { get; set; }
}
