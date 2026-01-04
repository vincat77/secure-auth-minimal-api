using Microsoft.AspNetCore.Http;
using SecureAuthMinimalApi.Data;
using SecureAuthMinimalApi.Models;

namespace SecureAuthMinimalApi.Endpoints;

internal static class EndpointUtilities
{
    public static byte[] RandomBytes(int len)
    {
        var buffer = new byte[len];
        System.Security.Cryptography.RandomNumberGenerator.Fill(buffer);
        return buffer;
    }

    public static string Base64Url(byte[] bytes)
    {
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

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

    public static string? NormalizeUsername(string? username, bool forceLower)
    {
        if (string.IsNullOrWhiteSpace(username))
            return null;
        var trimmed = username.Trim();
        return forceLower ? trimmed.ToLowerInvariant() : trimmed;
    }

    public static string? NormalizeEmail(string? email)
    {
        if (string.IsNullOrWhiteSpace(email))
            return null;
        return email.Trim().ToLowerInvariant();
    }
}
