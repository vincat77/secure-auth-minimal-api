namespace SecureAuthMinimalApi;

/// <summary>
/// DTO per la richiesta di login contenente credenziali, MFA e flag remember-me.
/// </summary>
public sealed record LoginRequest(string? Username, string? Password, string? TotpCode, bool RememberMe, string? Nonce);
