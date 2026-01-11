using Microsoft.AspNetCore.Http;
using SecureAuthMinimalApi.Models;

namespace SecureAuthMinimalApi.Filters;

/// <summary>
/// Placeholder per enforcement MFA: richiede che la sessione esista; la verifica del livello MFA avverrà quando sarà disponibile un flag esplicito.
/// </summary>
public sealed class MfaFilter : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        if (context.HttpContext.Items["session"] is not UserSession session)
        {
            return Results.Unauthorized();
        }

        return await next(context);
    }
}
