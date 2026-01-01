using SecureAuthMinimalApi.Models;

namespace SecureAuthMinimalApi.Middleware;

/// <summary>
/// Implementa il Synchronized Token Pattern: confronta l'header X-CSRF-Token con il token in sessione.
/// Applica il controllo solo ai metodi unsafe e solo agli endpoint protetti.
/// </summary>
public sealed class CsrfMiddleware : IMiddleware
{
    private static readonly HashSet<string> UnsafeMethods = new(StringComparer.OrdinalIgnoreCase)
        { HttpMethods.Post, HttpMethods.Put, HttpMethods.Patch, HttpMethods.Delete };
    private readonly ILogger<CsrfMiddleware> _logger;

    public CsrfMiddleware(ILogger<CsrfMiddleware> logger)
    {
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        // Synchronized Token Pattern (hardened):
        // - token generated server-side
        // - stored ONLY in DB (inside the session row)
        // - client must send X-CSRF-Token header
        // - middleware compares header token with DB token
        if (UnsafeMethods.Contains(context.Request.Method))
        {
            // Skip login/health for DX; logout and other protected endpoints will have session.
            var path = context.Request.Path.Value ?? "";
            var isPublic = path.Equals("/login", StringComparison.OrdinalIgnoreCase)
                        || path.Equals("/health", StringComparison.OrdinalIgnoreCase)
                        || path.Equals("/register", StringComparison.OrdinalIgnoreCase)
                        || path.Equals("/confirm-email", StringComparison.OrdinalIgnoreCase)
                        || path.Equals("/refresh", StringComparison.OrdinalIgnoreCase);

            if (!isPublic)
            {
                if (!context.Items.TryGetValue("session", out var sObj) || sObj is not UserSession session)
                {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsJsonAsync(new { ok = false, error = "unauthorized" });
                    _logger.LogWarning("CSRF KO nessuna sessione {Method} {Path}", context.Request.Method, path);
                    return;
                }

                var headerToken = context.Request.Headers["X-CSRF-Token"].ToString();
                if (string.IsNullOrWhiteSpace(headerToken) ||
                    !FixedTimeEquals(headerToken, session.CsrfToken))
                {
                    context.Response.StatusCode = StatusCodes.Status403Forbidden;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsJsonAsync(new { ok = false, error = "csrf_invalid" });
                    _logger.LogWarning("CSRF KO token invalido sessionId={SessionId} userId={UserId} {Method} {Path}", session.SessionId, session.UserId, context.Request.Method, path);
                    return;
                }
                _logger.LogInformation("CSRF OK sessionId={SessionId} userId={UserId} {Method} {Path}", session.SessionId, session.UserId, context.Request.Method, path);
            }
        }

        await next(context);
    }

    private static bool FixedTimeEquals(string a, string b)
    {
        // constant time compare to reduce token oracle risk
        var aBytes = System.Text.Encoding.UTF8.GetBytes(a);
        var bBytes = System.Text.Encoding.UTF8.GetBytes(b);
        return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(aBytes, bBytes);
    }
}

public static class CsrfExtensions
{
    public static IApplicationBuilder UseCsrfProtection(this IApplicationBuilder app)
        => app.UseMiddleware<CsrfMiddleware>();
}
