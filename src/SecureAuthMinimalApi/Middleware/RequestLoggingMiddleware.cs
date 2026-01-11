using System.Text.Json;

namespace SecureAuthMinimalApi.Middleware;

/// <summary>
/// Logga inizio/fine richiesta e converte UnauthorizedAccessException in 401 JSON.
/// </summary>
public sealed class RequestLoggingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<RequestLoggingMiddleware> _logger;

    public RequestLoggingMiddleware(RequestDelegate next, ILogger<RequestLoggingMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            _logger.LogInformation("Richiesta inizio {Method} {Path}", context.Request.Method, context.Request.Path);
            await _next(context);
            _logger.LogInformation("Richiesta fine {Status} {Method} {Path}", context.Response.StatusCode, context.Request.Method, context.Request.Path);
        }
        catch (UnauthorizedAccessException)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(JsonSerializer.Serialize(new { ok = false, error = "unauthorized" }));
            _logger.LogWarning("Richiesta fine 401 Non Autorizzato {Method} {Path}", context.Request.Method, context.Request.Path);
        }
    }
}
