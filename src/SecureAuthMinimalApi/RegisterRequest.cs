namespace SecureAuthMinimalApi;

/// <summary>
/// DTO per la registrazione di un nuovo utente con metadata opzionali.
/// </summary>
public sealed record RegisterRequest(string? Username, string? Email, string? Password, string? Name, string? GivenName, string? FamilyName, string? Picture);
