using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using SecureAuthMinimalApi.Filters;
using SecureAuthMinimalApi.Models;
using SecureAuthMinimalApi.Tests.Filters;
using Xunit;

namespace SecureAuthMinimalApi.Tests.Filters;

public class SessionFilterTests
{
    [Fact]
    public async Task SessionFilter_NoSession_Returns401()
    {
        var httpContext = new DefaultHttpContext();
        var filter = new SessionFilter();
        var ctx = FilterTestHelpers.CreateInvocationContext(httpContext);

        var result = await filter.InvokeAsync(ctx, _ => ValueTask.FromResult<object?>(Results.Ok()));

        Assert.IsType<UnauthorizedHttpResult>(result);
    }

    [Fact]
    public async Task SessionFilter_WithSession_CallsNext()
    {
        var httpContext = new DefaultHttpContext();
        httpContext.Items["session"] = NewSession();
        var filter = new SessionFilter();
        var ctx = FilterTestHelpers.CreateInvocationContext(httpContext);
        var called = false;

        await filter.InvokeAsync(ctx, _ =>
        {
            called = true;
            return ValueTask.FromResult<object?>(Results.Ok());
        });

        Assert.True(called);
    }

    private static UserSession NewSession() => new()
    {
        SessionId = "s1",
        UserId = "u1",
        CreatedAtUtc = DateTime.UtcNow.ToString("O"),
        ExpiresAtUtc = DateTime.UtcNow.AddMinutes(5).ToString("O"),
        RevokedAtUtc = null,
        UserDataJson = "{}",
        CsrfToken = "token",
        LastSeenUtc = DateTime.UtcNow.ToString("O")
    };
}
