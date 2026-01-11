using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using SecureAuthMinimalApi.Filters;
using SecureAuthMinimalApi.Models;
using Xunit;

namespace SecureAuthMinimalApi.Tests.Filters;

public class CsrfFilterTests
{
    [Fact]
    public async Task CsrfFilter_NoSession_Returns401()
    {
        var httpContext = new DefaultHttpContext();
        var filter = new CsrfFilter();
        var ctx = FilterTestHelpers.CreateInvocationContext(httpContext);

        var result = await filter.InvokeAsync(ctx, _ => ValueTask.FromResult<object?>(Results.Ok()));

        Assert.IsType<UnauthorizedHttpResult>(result);
    }

    [Fact]
    public async Task CsrfFilter_NoHeader_Returns403()
    {
        var httpContext = new DefaultHttpContext();
        httpContext.Items["session"] = NewSession("abc");
        var filter = new CsrfFilter();
        var ctx = FilterTestHelpers.CreateInvocationContext(httpContext);

        var result = await filter.InvokeAsync(ctx, _ => ValueTask.FromResult<object?>(Results.Ok()));

        var status = Assert.IsAssignableFrom<IStatusCodeHttpResult>(result);
        Assert.Equal(StatusCodes.Status403Forbidden, status.StatusCode);
    }

    [Fact]
    public async Task CsrfFilter_WrongToken_Returns403()
    {
        var httpContext = new DefaultHttpContext();
        httpContext.Items["session"] = NewSession("abc");
        httpContext.Request.Headers["X-CSRF-Token"] = "wrong";
        var filter = new CsrfFilter();
        var ctx = FilterTestHelpers.CreateInvocationContext(httpContext);

        var result = await filter.InvokeAsync(ctx, _ => ValueTask.FromResult<object?>(Results.Ok()));

        var status = Assert.IsAssignableFrom<IStatusCodeHttpResult>(result);
        Assert.Equal(StatusCodes.Status403Forbidden, status.StatusCode);
    }

    [Fact]
    public async Task CsrfFilter_ValidToken_CallsNext()
    {
        var httpContext = new DefaultHttpContext();
        httpContext.Items["session"] = NewSession("abc");
        httpContext.Request.Headers["X-CSRF-Token"] = "abc";
        var filter = new CsrfFilter();
        var ctx = FilterTestHelpers.CreateInvocationContext(httpContext);
        var called = false;

        await filter.InvokeAsync(ctx, _ =>
        {
            called = true;
            return ValueTask.FromResult<object?>(Results.Ok());
        });

        Assert.True(called);
    }

    private static UserSession NewSession(string csrf) => new()
    {
        SessionId = "s1",
        UserId = "u1",
        CreatedAtUtc = DateTime.UtcNow.ToString("O"),
        ExpiresAtUtc = DateTime.UtcNow.AddMinutes(5).ToString("O"),
        RevokedAtUtc = null,
        UserDataJson = "{}",
        CsrfToken = csrf,
        LastSeenUtc = DateTime.UtcNow.ToString("O")
    };
}
