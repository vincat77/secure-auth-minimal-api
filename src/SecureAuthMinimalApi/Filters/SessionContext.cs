using SecureAuthMinimalApi.Models;

namespace SecureAuthMinimalApi.Filters;

/// <summary>
/// DTO per esporre la sessione agli handler quando serve dependency injection esplicita.
/// </summary>
public sealed record SessionContext(UserSession Session);
