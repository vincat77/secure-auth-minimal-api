using SecureAuthMinimalApi.Data;
using SecureAuthMinimalApi.Middleware;
using SecureAuthMinimalApi.Models;
using SecureAuthMinimalApi.Options;
using SecureAuthMinimalApi.Services;
using SecureAuthMinimalApi.Endpoints;
using Serilog;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);

var hostUrls = builder.Configuration.GetSection("Hosting:Urls").Get<string[]>();
if (hostUrls?.Length > 0)
{
  builder.WebHost.UseUrls(hostUrls);
}

Log.Logger = new LoggerConfiguration()
    .ReadFrom.Configuration(builder.Configuration)
    .Enrich.FromLogContext()
    .CreateLogger();

builder.Host.UseSerilog();
using var loggerFactory = LoggerFactory.Create(b => b.AddSerilog());
var logger = loggerFactory.CreateLogger<Program>();
var cleanupOptions = builder.Configuration.GetSection("Cleanup").Get<CleanupOptions>() ?? new CleanupOptions();
var resetOptions = builder.Configuration.GetSection("PasswordReset").Get<PasswordResetOptions>() ?? new PasswordResetOptions();

logger.LogInformation(
    "Cleanup configurazione: enabled={Enabled}, intervalSeconds={Interval}, batchSize={Batch}, maxIterations={MaxIterations}",
    cleanupOptions.Enabled,
    cleanupOptions.IntervalSeconds,
    cleanupOptions.BatchSize,
    cleanupOptions.MaxIterationsPerRun?.ToString() ?? "null");

// L'errore di configurazione per secret mancante o troppo corto viene gestito da JwtTokenService.
builder.Services.AddSingleton<JwtTokenService>();
builder.Services.AddSingleton<SessionRepository>();
builder.Services.AddSingleton<UserRepository>();
builder.Services.AddSingleton<LoginThrottleRepository>();
builder.Services.AddSingleton<ILoginThrottle, DbLoginThrottle>();
builder.Services.AddSingleton<LoginAuditRepository>();

// DataProtection con chiavi persistenti (evita invalidazioni dopo restart/deploy)
var dpKeysPath = builder.Configuration["DataProtection:KeysPath"];
if (string.IsNullOrWhiteSpace(dpKeysPath))
{
  dpKeysPath = Path.Combine(builder.Environment.ContentRootPath, ".dpkeys");
}

builder.Services.AddDataProtection()
    .SetApplicationName("SecureAuthMinimalApi")
    .PersistKeysToFileSystem(new DirectoryInfo(dpKeysPath));
builder.Services.AddSingleton<TotpSecretProtector>();
builder.Services.AddSingleton<RefreshTokenHasher>();
builder.Services.AddSingleton<RefreshTokenRepository>();
builder.Services.AddSingleton<MfaChallengeRepository>();
builder.Services.AddSingleton<PasswordResetRepository>();
builder.Services.AddSingleton<IdTokenService>();
builder.Services.AddSingleton<IEmailService, NoopEmailService>();
builder.Services.AddSingleton<PauseController>();
builder.Services.AddSingleton<ConsoleControlService>();

builder.Services.Configure<PasswordResetOptions>(builder.Configuration.GetSection("PasswordReset"));
builder.Services.Configure<CleanupOptions>(builder.Configuration.GetSection("Cleanup"));
builder.Services.Configure<RefreshOptions>(builder.Configuration.GetSection("Refresh"));
builder.Services.Configure<CookieConfigOptions>(builder.Configuration.GetSection("Cookie"));
builder.Services.Configure<SessionConfigOptions>(builder.Configuration.GetSection("Session"));
builder.Services.Configure<ConnectionStringsOptions>(builder.Configuration.GetSection("ConnectionStrings"));
builder.Services.Configure<PasswordPolicyOptions>(builder.Configuration.GetSection("PasswordPolicy"));
builder.Services.Configure<RememberMeOptions>(builder.Configuration.GetSection("RememberMe"));
builder.Services.Configure<DeviceOptions>(builder.Configuration.GetSection("Device"));
builder.Services.Configure<JwtOptions>(builder.Configuration.GetSection("Jwt"));
builder.Services.Configure<IdTokenOptions>(builder.Configuration.GetSection("IdToken"));
builder.Services.Configure<UsernamePolicyOptions>(builder.Configuration.GetSection("UsernamePolicy"));
builder.Services.Configure<MfaOptions>(builder.Configuration.GetSection("Mfa"));
builder.Services.Configure<LoginThrottleOptions>(builder.Configuration.GetSection("LoginThrottle"));
builder.Services.Configure<EmailConfirmationOptions>(options =>
{
  var raw = builder.Configuration["EmailConfirmation:Required"];
  if (string.IsNullOrWhiteSpace(raw))
  {
    options.Required = true;
    return;
  }

  if (!bool.TryParse(raw, out var parsed))
  {
    options.Required = true;
    logger.LogWarning("EmailConfirmation:Required non valido ({Value}), fallback a true", raw);
    return;
  }

  options.Required = parsed;
});

builder.Services.AddHostedService<ExpiredCleanupService>();
builder.Services.AddLogging();

builder.Services.AddTransient<CookieJwtAuthMiddleware>();
builder.Services.AddTransient<CsrfMiddleware>();

var app = builder.Build();
var isDevelopment = app.Environment.IsDevelopment();
var pauseController = app.Services.GetRequiredService<PauseController>();

var passwordPolicyOptions = app.Services.GetRequiredService<IOptions<PasswordPolicyOptions>>().Value;
var usernamePolicyOptions = app.Services.GetRequiredService<IOptions<UsernamePolicyOptions>>().Value;
var emailConfirmationOptions = app.Services.GetRequiredService<IOptions<EmailConfirmationOptions>>().Value;
var mfaOptions = app.Services.GetRequiredService<IOptions<MfaOptions>>().Value;
var jwtOptions = app.Services.GetRequiredService<IOptions<JwtOptions>>().Value;
var rememberMeOptions = app.Services.GetRequiredService<IOptions<RememberMeOptions>>().Value;
var deviceOptions = app.Services.GetRequiredService<IOptions<DeviceOptions>>().Value;
var sessionOptions = app.Services.GetRequiredService<IOptions<SessionConfigOptions>>().Value;
var connectionStrings = app.Services.GetRequiredService<IOptions<ConnectionStringsOptions>>().Value;
var refreshOptions = app.Services.GetRequiredService<IOptions<RefreshOptions>>().Value;
var idTokenOptions = app.Services.GetRequiredService<IOptions<IdTokenOptions>>().Value;
var loginThrottleOptions = app.Services.GetRequiredService<IOptions<LoginThrottleOptions>>().Value;
var cookieOptions = app.Services.GetRequiredService<IOptions<CookieConfigOptions>>().Value;
if (mfaOptions.ChallengeMinutes <= 0)
{
  throw new InvalidOperationException("Mfa:ChallengeMinutes deve essere >= 1");
}

var loginOptions = new LoginOptions
{
  ForceLowerUsername = usernamePolicyOptions.Lowercase,
  EmailConfirmationRequired = emailConfirmationOptions.Required,
  MfaChallengeMinutes = mfaOptions.ChallengeMinutes,
  MfaRequireUaMatch = mfaOptions.RequireUaMatch,
  MfaRequireIpMatch = mfaOptions.RequireIpMatch,
  MfaMaxAttempts = mfaOptions.MaxAttemptsPerChallenge
};

app.EnsureDatabaseInitialized(logger);

// Validazioni config in ambiente non Development.
app.ValidateJwt(logger);
app.ValidateCookieSecurity(logger);
app.LogStartupInfo(logger);

// Middleware ordine personalizzato
app.UseRequestLoggingWithUnauthorizedHandling();

// Hardening header solo fuori da Development.
if (!isDevelopment)
{
  app.UseHsts();
  app.UseHttpsRedirection();
  app.UseSecurityHeaders();
}

// Middleware pausa basato su flag condiviso
app.UsePauseMiddleware(new Func<bool>(() => pauseController.IsPaused));

// --- ORDINE DEI MIDDLEWARE (OBBLIGATORIO) ---
// 1) Cookie JWT auth popola HttpContext.Items["session"]
app.UseCookieJwtAuth();

// 2) Protezione CSRF legge la sessione da HttpContext.Items["session"]
app.UseCsrfProtection();

// 3) Endpoint
app.MapHealth();
app.MapLive();
app.MapReady();
app.MapRegister();
app.MapLogin();
app.MapConfirmMfa();
app.MapMe();
app.MapChangePassword();
app.MapChangeEmail();
app.MapLogout();
app.MapMfaSetup();
app.MapMfaDisable();
app.MapConfirmEmail();
app.MapLogoutAll();
app.MapRefresh();
app.MapIntrospect();
app.MapPasswordReset();

var shutdownCts = new CancellationTokenSource();
var appTask = app.RunAsync(shutdownCts.Token);
var consoleService = app.Services.GetRequiredService<ConsoleControlService>();
var consoleTask = consoleService.RunAsync(shutdownCts, app);

if (ReferenceEquals(consoleTask, Task.CompletedTask))
{
  // In ambienti senza input console (es. test host), lascia girare solo l'app.
  await appTask;
}
else
{
  await Task.WhenAny(appTask, consoleTask);
  shutdownCts.Cancel();

  try
  {
    await Task.WhenAll(appTask, consoleTask);
  }
  catch (OperationCanceledException)
  {
    // Shutdown richiesto dall'utente o dall'host.
  }
}



/// <summary>
/// Classe parziale necessaria per abilitare i test/integrazione di WebApplicationFactory.
/// </summary>
public partial class Program { }

