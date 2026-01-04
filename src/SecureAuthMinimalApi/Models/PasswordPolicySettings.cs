namespace SecureAuthMinimalApi.Models;

/// <summary>
/// Impostazioni della policy password (min length, requisiti di carattere).
/// </summary>
public sealed record PasswordPolicySettings(int MinLength, bool RequireUpper, bool RequireLower, bool RequireDigit, bool RequireSymbol);
