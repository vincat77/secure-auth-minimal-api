using Microsoft.AspNetCore.Http;

namespace SecureAuthMinimalApi.Tests.Filters;

internal static class FilterTestHelpers
{
    internal static EndpointFilterInvocationContext CreateInvocationContext(HttpContext httpContext)
    {
        return new DefaultEndpointFilterInvocationContext(httpContext, Array.Empty<object?>());
    }
}
