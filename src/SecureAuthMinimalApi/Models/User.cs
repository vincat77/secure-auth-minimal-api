namespace SecureAuthMinimalApi.Models;

/// <summary>
/// Modello utente persistito (password hashata, username univoco).
/// </summary>
public sealed class User
{
    public required string Id { get; init; }
    public required string Username { get; init; }
    public required string PasswordHash { get; init; }
    public required string CreatedAtUtc { get; init; }
    public string? TotpSecret { get; init; }
}
