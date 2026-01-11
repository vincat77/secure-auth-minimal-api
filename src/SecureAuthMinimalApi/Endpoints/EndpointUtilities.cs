using Microsoft.AspNetCore.Http;
using SecureAuthMinimalApi.Data;
using SecureAuthMinimalApi.Models;

namespace SecureAuthMinimalApi.Endpoints;

internal static class EndpointUtilities
{
    /// <summary>
    /// Registra un evento di audit login con i metadati della richiesta.
    /// </summary>
    public static Task AuditAsync(LoginAuditRepository repo, string username, string outcome, HttpContext ctx, string? detail)
    {
        var audit = new LoginAudit
        {
            Id = Guid.NewGuid().ToString("N"),
            Username = username,
            Outcome = outcome,
            TimestampUtc = DateTime.UtcNow.ToString("O"),
            ClientIp = ctx.Connection.RemoteIpAddress?.ToString(),
            UserAgent = ctx.Request.Headers["User-Agent"].ToString(),
            Detail = detail
        };
        return repo.CreateAsync(audit, ctx.RequestAborted);
    }

    /// <summary>
    /// Normalizza lo username con trimming e lowercase opzionale.
    /// </summary>
    public static string? NormalizeUsername(string? username, bool forceLower)
    {
        if (string.IsNullOrWhiteSpace(username))
            return null;
        var trimmed = username.Trim();
        return forceLower ? trimmed.ToLowerInvariant() : trimmed;
    }

    /// <summary>
    /// Normalizza l'email con trimming e lowercase.
    /// </summary>
    public static string? NormalizeEmail(string? email)
    {
        if (string.IsNullOrWhiteSpace(email))
            return null;
        return email.Trim().ToLowerInvariant();
    }
}
