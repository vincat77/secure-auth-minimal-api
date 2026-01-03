namespace SecureAuthMinimalApi.Models;

public sealed record ChangePasswordRequest(string? CurrentPassword, string? NewPassword, string? ConfirmPassword);

public sealed record ChangePasswordResponse(bool Ok, string? Error = null, IEnumerable<string>? Errors = null, string? CsrfToken = null);
