namespace SecureAuthMinimalApi.Models;

/// <summary>
/// Payload per la richiesta di reset password.
/// </summary>
public sealed record PasswordResetRequest(string? Email);
