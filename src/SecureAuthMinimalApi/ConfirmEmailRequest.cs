namespace SecureAuthMinimalApi;

/// <summary>
/// DTO per la conferma email tramite token.
/// </summary>
public sealed record ConfirmEmailRequest(string? Token);
