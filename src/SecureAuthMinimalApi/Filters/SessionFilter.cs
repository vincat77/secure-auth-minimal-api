using SecureAuthMinimalApi.Models;

namespace SecureAuthMinimalApi.Filters;

/// <summary>
/// Verifica che la sessione sia presente in HttpContext.Items["session"] (popolata dal middleware cookie JWT).
/// Restituisce 401 se la sessione manca.
/// </summary>
public sealed class SessionFilter : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        if (context.HttpContext.Items["session"] is not UserSession)
        {
            return Results.Unauthorized();
        }

        return await next(context);
    }
}
