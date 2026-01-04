namespace SecureAuthMinimalApi.Models;

public sealed record PasswordPolicySettings(int MinLength, bool RequireUpper, bool RequireLower, bool RequireDigit, bool RequireSymbol);
