namespace SecureAuthMinimalApi.Models;

/// <summary>
/// DTO per la conferma MFA contenente challenge, codice TOTP e flag remember-me.
/// </summary>
public sealed record ConfirmMfaRequest(string? ChallengeId, string? TotpCode, bool RememberMe, string? Nonce);
