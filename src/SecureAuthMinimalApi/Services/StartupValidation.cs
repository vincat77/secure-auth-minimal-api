using System.Text.Json;
using SecureAuthMinimalApi.Options;
using SecureAuthMinimalApi.Models;
using Microsoft.Extensions.Options;

namespace SecureAuthMinimalApi.Services;

/// <summary>
/// Controlli di sicurezza eseguiti all'avvio in ambienti non Development.
/// </summary>
public static class StartupValidation
{

  static IReadOnlyCollection<string> GetConfiguredUrls(WebApplication app)
  {
    if (app.Urls.Any())
      return app.Urls.ToArray();

    var envUrls = app.Configuration["ASPNETCORE_URLS"];
    if (!string.IsNullOrWhiteSpace(envUrls))
    {
      return envUrls.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    return new[] { "http://localhost:5000", "https://localhost:5001" };
  }


  /// <summary>
  /// Valida le impostazioni JWT (secret, issuer, audience).
  /// </summary>
  public static void ValidateJwt(WebApplication app, JwtOptions jwtOptions, ILogger logger)
  {
    if (app.Environment.IsDevelopment())
      return;

    if (string.IsNullOrWhiteSpace(jwtOptions.SecretKey))
    {
      throw new InvalidOperationException("Configurazione mancante: Jwt:SecretKey");
    }

    if (jwtOptions.SecretKey.Contains("CHANGE_ME", StringComparison.OrdinalIgnoreCase) ||
        jwtOptions.SecretKey.Contains("CHANGEME", StringComparison.OrdinalIgnoreCase) ||
        jwtOptions.SecretKey.Contains("REPLACE_ME", StringComparison.OrdinalIgnoreCase))
    {
      throw new InvalidOperationException("Jwt:SecretKey è un placeholder. Impostare un segreto reale in produzione.");
    }

    if (jwtOptions.SecretKey.Length < 32)
    {
      throw new InvalidOperationException("Jwt:SecretKey troppo corto (min 32 caratteri consigliati).");
    }

    var iss = jwtOptions.Issuer ?? "";
    var aud = jwtOptions.Audience ?? "";
    if (!iss.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ||
        !aud.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
    {
      logger.LogWarning("Jwt Issuer/Audience non HTTPS in ambiente non Development: iss={Issuer}, aud={Audience}", iss, aud);
    }
  }

  /// <summary>
  /// Valida le impostazioni cookie di sicurezza.
  /// </summary>
  public static void ValidateCookieSecurity(WebApplication app, CookieConfigOptions cookieOptions, ILogger logger)
  {
    if (app.Environment.IsDevelopment())
      return;

    if (!cookieOptions.RequireSecure)
    {
      logger.LogWarning("Cookie:RequireSecure=false in ambiente non Development: sarà forzato a true");
    }
  }

  /// <summary>
  /// Logga la configurazione effettiva all'avvio (per diagnostica).
  /// </summary>
  public static void LogStartupInfo(WebApplication app, ILogger logger)
  {
    var cleanup = app.Services.GetRequiredService<IOptions<CleanupOptions>>().Value;
    var passwordPolicy = app.Services.GetRequiredService<IOptions<PasswordPolicyOptions>>().Value;
    var usernamePolicy = app.Services.GetRequiredService<IOptions<UsernamePolicyOptions>>().Value;
    var emailConfirmation = app.Services.GetRequiredService<IOptions<EmailConfirmationOptions>>().Value;
    var mfa = app.Services.GetRequiredService<IOptions<MfaOptions>>().Value;
    var reset = app.Services.GetRequiredService<IOptions<PasswordResetOptions>>().Value;
    var jwt = app.Services.GetRequiredService<IOptions<JwtOptions>>().Value;
    var rememberMe = app.Services.GetRequiredService<IOptions<RememberMeOptions>>().Value;
    var device = app.Services.GetRequiredService<IOptions<DeviceOptions>>().Value;
    var session = app.Services.GetRequiredService<IOptions<SessionConfigOptions>>().Value;
    var connectionStrings = app.Services.GetRequiredService<IOptions<ConnectionStringsOptions>>().Value;
    var refreshOptions = app.Services.GetRequiredService<IOptions<RefreshOptions>>().Value;
    var idTokenOptions = app.Services.GetRequiredService<IOptions<IdTokenOptions>>().Value;
    var loginThrottle = app.Services.GetRequiredService<IOptions<LoginThrottleOptions>>().Value;

    var startupConfig = new
    {
      Environment = app.Environment.EnvironmentName,
      ContentRoot = app.Environment.ContentRootPath,
      Urls = GetConfiguredUrls(app),
      Database = connectionStrings.Sqlite ?? "<missing>",
      Jwt = new
      {
        Issuer = jwt.Issuer ?? "<missing>",
        Audience = jwt.Audience ?? "<missing>",
        SecretLength = jwt.SecretKey?.Length ?? 0
      },
      PasswordPolicy = new
      {
        MinLength = passwordPolicy.EffectiveMinLength,
        RequireUpper = passwordPolicy.RequireUpper,
        RequireLower = passwordPolicy.RequireLower,
        RequireDigit = passwordPolicy.RequireDigit,
        RequireSymbol = passwordPolicy.RequireSymbol
      },
      UsernamePolicy = new { Lowercase = usernamePolicy.Lowercase },
      EmailConfirmation = new { Required = emailConfirmation.Required },
      Mfa = new
      {
        ChallengeMinutes = mfa.ChallengeMinutes,
        RequireUaMatch = mfa.RequireUaMatch,
        RequireIpMatch = mfa.RequireIpMatch,
        MaxAttemptsPerChallenge = mfa.MaxAttemptsPerChallenge
      },
      SessionIdleMinutes = session.IdleMinutes,
      PasswordReset = new
      {
        ExpirationMinutes = reset.ExpirationMinutes,
        RequireConfirmed = reset.RequireConfirmed,
        IncludeTokenInResponseForTesting = app.Environment.IsDevelopment() && reset.IncludeTokenInResponseForTesting,
        RetentionDays = reset.RetentionDays
      },
      RememberMe = new
      {
        CookieName = rememberMe.CookieName,
        Path = rememberMe.Path,
        RequireSecure = rememberMe.RequireSecure,
        SameSite = rememberMe.SameSite,
        AllowSameSiteNone = rememberMe.AllowSameSiteNone
      },
      Device = new
      {
        CookieName = device.CookieName,
        RequireSecure = device.RequireSecure,
        PersistDays = device.PersistDays,
        SameSite = device.SameSite,
        AllowSameSiteNone = device.AllowSameSiteNone
      },
      Cleanup = new
      {
        Enabled = cleanup.Enabled,
        IntervalSeconds = cleanup.IntervalSeconds,
        BatchSize = cleanup.BatchSize,
        MaxIterationsPerRun = cleanup.MaxIterationsPerRun
      },
      LoginThrottle = new
      {
        MaxFailures = loginThrottle.MaxFailures,
        LockMinutes = loginThrottle.LockMinutes
      },
      IdToken = new
      {
        Issuer = idTokenOptions.Issuer,
        Audience = idTokenOptions.Audience,
        Minutes = idTokenOptions.Minutes
      },
      SkipDbInit = app.Configuration.GetValue<bool?>("Tests:SkipDbInit") ?? false
  };

    var formatted = JsonSerializer.Serialize(startupConfig, new JsonSerializerOptions { WriteIndented = true });
    logger.LogInformation("Avvio SecureAuthMinimalApi - configurazione attiva:\n{StartupConfig}", formatted);
    logger.LogInformation("Console pronta: 'P' per pausa/ripresa, 'S' per arresto.");

    app.Lifetime.ApplicationStarted.Register(() =>
    {
      var addresses = app.Urls.Any() ? app.Urls.ToArray() : GetConfiguredUrls(app).ToArray();
      logger.LogInformation("SecureAuthMinimalApi in ascolto su: {Urls}", string.Join(", ", addresses));
    });
  }
}
