using SecureAuthMinimalApi.Models;

namespace SecureAuthMinimalApi;

public static class AuthHelpers
{
    public static UserSession GetRequiredSession(this HttpContext ctx)
    {
        if (ctx.Items.TryGetValue("session", out var sObj) && sObj is UserSession s)
            return s;

        throw new UnauthorizedAccessException();
    }

    // Estrae il token dal header Authorization Bearer o dal cookie access_token.
    public static bool TryGetToken(HttpContext ctx, out string token)
    {
        token = "";
        var authHeader = ctx.Request.Headers["Authorization"].ToString();
        if (!string.IsNullOrWhiteSpace(authHeader) && authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            token = authHeader["Bearer ".Length..].Trim();
            return !string.IsNullOrWhiteSpace(token);
        }

        if (ctx.Request.Cookies.TryGetValue("access_token", out var cookieToken) && !string.IsNullOrWhiteSpace(cookieToken))
        {
            token = cookieToken;
            return true;
        }

        return false;
    }

    public static List<string> ValidatePassword(string password, int minLength, bool requireUpper, bool requireLower, bool requireDigit, bool requireSymbol)
    {
        var errors = new List<string>();
        if (password.Length < minLength)
            errors.Add("too_short");
        if (requireUpper && !password.Any(char.IsUpper))
            errors.Add("missing_upper");
        if (requireLower && !password.Any(char.IsLower))
            errors.Add("missing_lower");
        if (requireDigit && !password.Any(char.IsDigit))
            errors.Add("missing_digit");
        if (requireSymbol && !password.Any(ch => !char.IsLetterOrDigit(ch)))
            errors.Add("missing_symbol");
        return errors;
    }
}
