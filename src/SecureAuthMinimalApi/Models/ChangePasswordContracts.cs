namespace SecureAuthMinimalApi.Models;

/// <summary>
/// DTO per la richiesta di cambio password.
/// </summary>
public sealed record ChangePasswordRequest(string? CurrentPassword, string? NewPassword, string? ConfirmPassword);

/// <summary>
/// DTO di risposta al cambio password comprensivo di errori e CSRF.
/// </summary>
public sealed record ChangePasswordResponse(bool Ok, string? Error = null, IEnumerable<string>? Errors = null, string? CsrfToken = null);
