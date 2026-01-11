using System.Text.Json;
using SecureAuthMinimalApi.Data;
using SecureAuthMinimalApi.Middleware;
using SecureAuthMinimalApi.Models;
using SecureAuthMinimalApi.Options;
using SecureAuthMinimalApi.Services;
using SecureAuthMinimalApi.Endpoints;
using Serilog;
using Microsoft.AspNetCore.DataProtection;

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
var cleanupEnabled = builder.Configuration.GetValue<bool?>("Cleanup:Enabled") ?? true;
var cleanupInterval = builder.Configuration.GetValue<int?>("Cleanup:IntervalSeconds") ?? 300;
var cleanupBatch = builder.Configuration.GetValue<int?>("Cleanup:BatchSize") ?? 200;
var cleanupMaxIterations = builder.Configuration.GetValue<int?>("Cleanup:MaxIterationsPerRun");
var resetExpirationMinutes = builder.Configuration.GetValue<int?>("PasswordReset:ExpirationMinutes") ?? 30;
var resetRequireConfirmed = builder.Configuration.GetValue<bool?>("PasswordReset:RequireConfirmed") ?? true;
var resetIncludeToken = builder.Configuration.GetValue<bool?>("PasswordReset:IncludeTokenInResponseForTesting") ?? false;
var resetRetentionDays = builder.Configuration.GetValue<int?>("PasswordReset:RetentionDays") ?? 7;
logger.LogInformation(
    "Cleanup configurazione: enabled={Enabled}, intervalSeconds={Interval}, batchSize={Batch}, maxIterations={MaxIterations}",
    cleanupEnabled,
    cleanupInterval,
    cleanupBatch,
    cleanupMaxIterations?.ToString() ?? "null");

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
builder.Services.AddHostedService<ExpiredCleanupService>();
builder.Services.AddLogging();

builder.Services.AddTransient<CookieJwtAuthMiddleware>();
builder.Services.AddTransient<CsrfMiddleware>();

var app = builder.Build();
var isDevelopment = app.Environment.IsDevelopment();
var pauseFlag = 0;

var passwordPolicyOptions = app.Services.GetRequiredService<Microsoft.Extensions.Options.IOptions<PasswordPolicyOptions>>().Value;
var forceLowerUsername = app.Configuration.GetValue<bool?>("UsernamePolicy:Lowercase") ?? false;
var emailRequiredRaw = app.Configuration["EmailConfirmation:Required"];
bool emailConfirmationRequired;
if (string.IsNullOrWhiteSpace(emailRequiredRaw))
{
    emailConfirmationRequired = true;
}
else if (!bool.TryParse(emailRequiredRaw, out emailConfirmationRequired))
{
    emailConfirmationRequired = true;
    logger.LogWarning("EmailConfirmation:Required non valido ({Value}), fallback a true", emailRequiredRaw);
}
var mfaChallengeMinutes = app.Configuration.GetValue<int?>("Mfa:ChallengeMinutes") ?? 10;
if (mfaChallengeMinutes <= 0)
{
    throw new InvalidOperationException("Mfa:ChallengeMinutes deve essere >= 1");
}
var mfaRequireUaMatch = app.Configuration.GetValue<bool?>("Mfa:RequireUaMatch") ?? true;
var mfaRequireIpMatch = app.Configuration.GetValue<bool?>("Mfa:RequireIpMatch") ?? false;
var mfaMaxAttempts = app.Configuration.GetValue<int?>("Mfa:MaxAttemptsPerChallenge") ?? 5;
var loginOptions = new LoginOptions
{
    ForceLowerUsername = forceLowerUsername,
    EmailConfirmationRequired = emailConfirmationRequired,
    MfaChallengeMinutes = mfaChallengeMinutes,
    MfaRequireUaMatch = mfaRequireUaMatch,
    MfaRequireIpMatch = mfaRequireIpMatch,
    MfaMaxAttempts = mfaMaxAttempts
};

var skipDbInit = app.Configuration.GetValue<bool?>("Tests:SkipDbInit") ?? false;
if (skipDbInit)
{
    logger.LogWarning("Avvio con Tests:SkipDbInit=true: saltata inizializzazione DB (solo per test)");
}
else
{
    DbInitializer.EnsureCreated(app.Configuration, app.Environment, logger);
}

// Validazioni config in ambiente non Development.
if (!isDevelopment)
{
    var secret = app.Configuration["Jwt:SecretKey"];
    if (string.IsNullOrWhiteSpace(secret))
    {
        throw new InvalidOperationException("Configurazione mancante: Jwt:SecretKey");
    }
    if (secret.Contains("CHANGE_ME", StringComparison.OrdinalIgnoreCase) ||
        secret.Contains("CHANGEME", StringComparison.OrdinalIgnoreCase) ||
        secret.Contains("REPLACE_ME", StringComparison.OrdinalIgnoreCase))
    {
        throw new InvalidOperationException("Jwt:SecretKey è un placeholder. Impostare un segreto reale in produzione.");
    }
    if (secret.Length < 32)
    {
        throw new InvalidOperationException("Jwt:SecretKey troppo corto (min 32 caratteri consigliati).");
    }

    var iss = app.Configuration["Jwt:Issuer"] ?? "";
    var aud = app.Configuration["Jwt:Audience"] ?? "";
    if (!iss.StartsWith("https://", StringComparison.OrdinalIgnoreCase) || !aud.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
    {
        logger.LogWarning("Jwt Issuer/Audience non HTTPS in ambiente non Development: iss={Issuer}, aud={Audience}", iss, aud);
    }

    var cookieSecureConfig = app.Configuration.GetValue<bool?>("Cookie:RequireSecure") ?? true;
    if (!cookieSecureConfig)
    {
        logger.LogWarning("Cookie:RequireSecure=false in ambiente non Development: sarà forzato a true");
    }
}

var serverUrls = GetConfiguredUrls(app);
LogStartupInfo(
    app,
    logger,
    serverUrls,
    cleanupEnabled,
    cleanupInterval,
    cleanupBatch,
    cleanupMaxIterations,
    passwordPolicyOptions.EffectiveMinLength,
    passwordPolicyOptions.RequireUpper,
    passwordPolicyOptions.RequireLower,
    passwordPolicyOptions.RequireDigit,
    passwordPolicyOptions.RequireSymbol,
    forceLowerUsername,
    emailConfirmationRequired,
    mfaChallengeMinutes,
    mfaRequireUaMatch,
    mfaRequireIpMatch,
    mfaMaxAttempts,
    skipDbInit,
    resetExpirationMinutes,
    resetRequireConfirmed,
    isDevelopment && resetIncludeToken,
    resetRetentionDays);

app.Lifetime.ApplicationStarted.Register(() =>
{
    var addresses = app.Urls.Any() ? app.Urls.ToArray() : serverUrls.ToArray();
    logger.LogInformation("SecureAuthMinimalApi in ascolto su: {Urls}", string.Join(", ", addresses));
});

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
app.UsePauseMiddleware(new Func<bool>(() => Volatile.Read(ref pauseFlag) == 1));

// --- ORDINE DEI MIDDLEWARE (OBBLIGATORIO) ---
// 1) Cookie JWT auth popola HttpContext.Items["session"]
app.UseCookieJwtAuth();

// 2) Protezione CSRF legge la sessione da HttpContext.Items["session"]
app.UseCsrfProtection();

// 3) Endpoint
app.MapHealth();
app.MapLive();
app.MapReady();
app.MapRegister(passwordPolicyOptions, forceLowerUsername);
app.MapLogin(loginOptions);
app.MapConfirmMfa(loginOptions);
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

if (Console.IsInputRedirected)
{
    logger.LogWarning("Input console non disponibile: arresto con Ctrl+C/TERM. Controlli P/S disabilitati.");
    await appTask;
    return;
}

var consoleTask = Task.Run(async () =>
{
    logger.LogInformation("Controlli console: premi 'P' per pausa/ripresa, 'S' per arresto sicuro.");
    while (!shutdownCts.IsCancellationRequested)
    {
        if (!Console.KeyAvailable)
        {
            await Task.Delay(250, shutdownCts.Token);
            continue;
        }

        var key = Console.ReadKey(intercept: true);
        if (key.Key == ConsoleKey.S)
        {
            logger.LogInformation("Arresto richiesto da console (S).");
            shutdownCts.Cancel();
            app.Lifetime.StopApplication();
            break;
        }

        if (key.Key == ConsoleKey.P)
        {
            var newValue = Volatile.Read(ref pauseFlag) == 0 ? 1 : 0;
            var previous = Interlocked.Exchange(ref pauseFlag, newValue);
            var isPausedNow = previous == 0;
            logger.LogWarning(isPausedNow ? "Applicazione messa in pausa: risposte 503 finche non viene ripresa." : "Pausa rimossa: ripresa gestione richieste.");
        }
    }
}, shutdownCts.Token);

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

static void LogStartupInfo(
    WebApplication app,
    Microsoft.Extensions.Logging.ILogger logger,
    IEnumerable<string> serverUrls,
    bool cleanupEnabled,
    int cleanupInterval,
    int cleanupBatch,
    int? cleanupMaxIterations,
    int minPasswordLength,
    bool requireUpper,
    bool requireLower,
    bool requireDigit,
    bool requireSymbol,
    bool forceLowerUsername,
    bool emailConfirmationRequired,
    int mfaChallengeMinutes,
    bool mfaRequireUaMatch,
    bool mfaRequireIpMatch,
    int mfaMaxAttempts,
    bool skipDbInit,
    int resetExpirationMinutes,
    bool resetRequireConfirmed,
    bool resetIncludeToken,
    int resetRetentionDays)
{
    var startupConfig = new
    {
        Environment = app.Environment.EnvironmentName,
        ContentRoot = app.Environment.ContentRootPath,
        Urls = serverUrls,
        Database = app.Configuration.GetConnectionString("Sqlite") ?? "<missing>",
        Jwt = new
        {
            Issuer = app.Configuration["Jwt:Issuer"] ?? "<missing>",
            Audience = app.Configuration["Jwt:Audience"] ?? "<missing>",
            SecretLength = app.Configuration["Jwt:SecretKey"]?.Length ?? 0
        },
        PasswordPolicy = new
        {
            MinLength = minPasswordLength,
            RequireUpper = requireUpper,
            RequireLower = requireLower,
            RequireDigit = requireDigit,
            RequireSymbol = requireSymbol
        },
        UsernamePolicy = new { Lowercase = forceLowerUsername },
        EmailConfirmation = new { Required = emailConfirmationRequired },
        Mfa = new
        {
            ChallengeMinutes = mfaChallengeMinutes,
            RequireUaMatch = mfaRequireUaMatch,
            RequireIpMatch = mfaRequireIpMatch,
            MaxAttemptsPerChallenge = mfaMaxAttempts
        },
        SessionIdleMinutes = app.Configuration.GetValue<int?>("Session:IdleMinutes"),
        PasswordReset = new
        {
            ExpirationMinutes = resetExpirationMinutes,
            RequireConfirmed = resetRequireConfirmed,
            IncludeTokenInResponseForTesting = resetIncludeToken,
            RetentionDays = resetRetentionDays
        },
        RememberMe = new
        {
            Days = app.Configuration.GetValue<int?>("RememberMe:Days"),
            CookieName = app.Configuration["RememberMe:CookieName"],
            Path = app.Configuration["RememberMe:Path"]
        },
        Device = new
        {
            CookieName = app.Configuration["Device:CookieName"],
            RequireSecure = app.Configuration.GetValue<bool?>("Device:RequireSecure"),
            PersistDays = app.Configuration.GetValue<int?>("Device:PersistDays")
        },
        Cleanup = new
        {
            Enabled = cleanupEnabled,
            IntervalSeconds = cleanupInterval,
            BatchSize = cleanupBatch,
            MaxIterationsPerRun = cleanupMaxIterations
        },
        LoginThrottle = new
        {
            MaxFailures = app.Configuration.GetValue<int?>("LoginThrottle:MaxFailures"),
            LockMinutes = app.Configuration.GetValue<int?>("LoginThrottle:LockMinutes")
        },
        IdToken = new
        {
            Issuer = app.Configuration["IdToken:Issuer"],
            Audience = app.Configuration["IdToken:Audience"],
            Minutes = app.Configuration.GetValue<int?>("IdToken:Minutes")
        },
        SkipDbInit = skipDbInit
    };

    var formatted = JsonSerializer.Serialize(startupConfig, new JsonSerializerOptions { WriteIndented = true });
    logger.LogInformation("Avvio SecureAuthMinimalApi - configurazione attiva:\n{StartupConfig}", formatted);
    logger.LogInformation("Console pronta: 'P' per pausa/ripresa, 'S' per arresto.");
}

/// <summary>
/// Classe parziale necessaria per abilitare i test/integrazione di WebApplicationFactory.
/// </summary>
public partial class Program { }

