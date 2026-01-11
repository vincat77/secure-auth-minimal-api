using SecureAuthMinimalApi.Models;
using SecureAuthMinimalApi.Utilities;

namespace SecureAuthMinimalApi.Filters;

/// <summary>
/// Implementa il controllo CSRF leggendo l'header X-CSRF-Token e confrontandolo con session.CsrfToken.
/// Richiede che la sessione sia già presente in HttpContext.Items["session"].
/// </summary>
public sealed class CsrfFilter : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var httpContext = context.HttpContext;

        if (httpContext.Items["session"] is not UserSession session)
        {
            return Results.Unauthorized();
        }

        if (!httpContext.Request.Headers.TryGetValue("X-CSRF-Token", out var headerToken) ||
            string.IsNullOrWhiteSpace(headerToken))
        {
            return Results.Json(new { ok = false, error = "csrf_missing" }, statusCode: StatusCodes.Status403Forbidden);
        }

        if (!SecurityUtils.FixedTimeEquals(headerToken!, session.CsrfToken))
        {
            return Results.Json(new { ok = false, error = "csrf_invalid" }, statusCode: StatusCodes.Status403Forbidden);
        }

        return await next(context);
    }
}
