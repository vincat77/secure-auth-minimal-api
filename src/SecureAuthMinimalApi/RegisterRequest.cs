namespace SecureAuthMinimalApi;

public sealed record RegisterRequest(string? Username, string? Email, string? Password, string? Name, string? GivenName, string? FamilyName, string? Picture);
