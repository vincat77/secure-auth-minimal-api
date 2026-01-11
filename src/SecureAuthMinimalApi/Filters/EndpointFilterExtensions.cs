namespace SecureAuthMinimalApi.Filters;

/// <summary>
/// Estensioni per applicare filtri compositivi sugli endpoint.
/// </summary>
public static class EndpointFilterExtensions
{
    public static RouteHandlerBuilder RequireSession(this RouteHandlerBuilder builder)
        => builder.AddEndpointFilter<SessionFilter>();

    public static RouteHandlerBuilder RequireCsrf(this RouteHandlerBuilder builder)
        => builder.AddEndpointFilter<CsrfFilter>();

    public static RouteHandlerBuilder RequireMfa(this RouteHandlerBuilder builder)
        => builder.AddEndpointFilter<MfaFilter>();
}
