namespace SecureAuthMinimalApi;

public sealed record ConfirmMfaRequest(string? ChallengeId, string? TotpCode, bool RememberMe, string? Nonce);
