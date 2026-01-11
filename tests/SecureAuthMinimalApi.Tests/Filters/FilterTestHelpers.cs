using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;

namespace SecureAuthMinimalApi.Tests.Filters;

internal static class FilterTestHelpers
{
    internal static EndpointFilterInvocationContext CreateInvocationContext(HttpContext httpContext)
    {
        return new DefaultEndpointFilterInvocationContext(httpContext, Array.Empty<object?>());
    }
}
