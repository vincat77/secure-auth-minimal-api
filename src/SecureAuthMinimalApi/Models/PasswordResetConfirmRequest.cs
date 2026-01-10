namespace SecureAuthMinimalApi.Models;

/// <summary>
/// Payload per confermare il reset password.
/// </summary>
public sealed record PasswordResetConfirmRequest(string? Token, string? NewPassword, string? ConfirmPassword);
