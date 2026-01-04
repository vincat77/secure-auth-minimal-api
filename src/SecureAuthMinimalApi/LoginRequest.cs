namespace SecureAuthMinimalApi;

public sealed record LoginRequest(string? Username, string? Password, string? TotpCode, bool RememberMe, string? Nonce);
