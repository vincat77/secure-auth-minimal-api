using System.Text.Json;
using SecureAuthMinimalApi.Data;
using SecureAuthMinimalApi.Middleware;
using SecureAuthMinimalApi.Models;
using SecureAuthMinimalApi.Services;
using SecureAuthMinimalApi.Endpoints;
using Serilog;
using Microsoft.Extensions.Logging;
using System.Threading;

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
builder.Services.AddDataProtection();
builder.Services.AddSingleton<TotpSecretProtector>();
builder.Services.AddSingleton<RefreshTokenHasher>();
builder.Services.AddSingleton<RefreshTokenRepository>();
builder.Services.AddSingleton<MfaChallengeRepository>();
builder.Services.AddSingleton<IdTokenService>();
builder.Services.Configure<CleanupOptions>(builder.Configuration.GetSection("Cleanup"));
builder.Services.AddHostedService<ExpiredCleanupService>();
builder.Services.AddLogging();

builder.Services.AddTransient<CookieJwtAuthMiddleware>();
builder.Services.AddTransient<CsrfMiddleware>();

var app = builder.Build();
var isDevelopment = app.Environment.IsDevelopment();
var pauseFlag = 0;

var configuredMin = app.Configuration.GetValue<int?>("PasswordPolicy:MinLength");
var minPasswordLength = configuredMin is null or < 1 ? 12 : configuredMin.Value;
var requireUpper = app.Configuration.GetValue<bool?>("PasswordPolicy:RequireUpper") ?? false;
var requireLower = app.Configuration.GetValue<bool?>("PasswordPolicy:RequireLower") ?? false;
var requireDigit = app.Configuration.GetValue<bool?>("PasswordPolicy:RequireDigit") ?? false;
var requireSymbol = app.Configuration.GetValue<bool?>("PasswordPolicy:RequireSymbol") ?? false;
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

var skipDbInit = app.Configuration.GetValue<bool?>("Tests:SkipDbInit") ?? false;
if (skipDbInit)
{
    logger.LogWarning("Avvio con Tests:SkipDbInit=true: saltata inizializzazione DB (solo per test)");
}
else
{
    DbInitializer.EnsureCreated(app.Configuration);
}

// Validazioni config in ambiente non Development.
if (!isDevelopment)
{
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
    minPasswordLength,
    requireUpper,
    requireLower,
    requireDigit,
    requireSymbol,
    forceLowerUsername,
    emailConfirmationRequired,
    mfaChallengeMinutes,
    mfaRequireUaMatch,
    mfaRequireIpMatch,
    mfaMaxAttempts,
    skipDbInit);

app.Lifetime.ApplicationStarted.Register(() =>
{
    var addresses = app.Urls.Any() ? app.Urls.ToArray() : serverUrls.ToArray();
    logger.LogInformation("SecureAuthMinimalApi in ascolto su: {Urls}", string.Join(", ", addresses));
});

// Hardening header solo fuori da Development.
if (!isDevelopment)
{
    app.UseHsts();
    app.UseHttpsRedirection();
    app.Use(async (ctx, next) =>
    {
        ctx.Response.Headers["X-Frame-Options"] = "DENY";
        ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
        ctx.Response.Headers["Referrer-Policy"] = "no-referrer";
        ctx.Response.Headers["X-XSS-Protection"] = "0";
        ctx.Response.Headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'";
        await next();
    });
}

// Converte UnauthorizedAccessException in 401 (sollevata solo dagli helper degli endpoint protetti).
app.Use(async (ctx, next) =>
{
    try
    {
        logger.LogInformation("Richiesta inizio {Method} {Path}", ctx.Request.Method, ctx.Request.Path);
        await next();
        logger.LogInformation("Richiesta fine {Status} {Method} {Path}", ctx.Response.StatusCode, ctx.Request.Method, ctx.Request.Path);
    }
    catch (UnauthorizedAccessException)
    {
        ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
        ctx.Response.ContentType = "application/json";
        await ctx.Response.WriteAsJsonAsync(new { ok = false, error = "unauthorized" });
        logger.LogWarning("Richiesta fine 401 Non Autorizzato {Method} {Path}", ctx.Request.Method, ctx.Request.Path);
    }
});

app.Use(async (ctx, next) =>
{
    if (Volatile.Read(ref pauseFlag) == 1)
    {
        logger.LogWarning("Richiesta respinta: applicazione in pausa {Method} {Path}", ctx.Request.Method, ctx.Request.Path);
        ctx.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
        await ctx.Response.WriteAsJsonAsync(new { ok = false, error = "paused" });
        return;
    }

    await next();
});

// --- ORDINE DEI MIDDLEWARE (OBBLIGATORIO) ---
// 1) Cookie JWT auth popola HttpContext.Items["session"]
app.UseCookieJwtAuth();

// 2) Protezione CSRF legge la sessione da HttpContext.Items["session"]
app.UseCsrfProtection();

// 3) Endpoint
app.MapHealth();
app.MapLive();
app.MapReady();
app.MapRegister(logger, minPasswordLength, requireUpper, requireLower, requireDigit, requireSymbol, forceLowerUsername);
app.MapLogin(logger, forceLowerUsername, emailConfirmationRequired, mfaChallengeMinutes, mfaRequireUaMatch, mfaRequireIpMatch, mfaMaxAttempts);
app.MapConfirmMfa(logger, mfaRequireUaMatch, mfaRequireIpMatch, mfaMaxAttempts);
app.MapMe();
app.MapChangePassword();
app.MapLogout(logger);
app.MapMfaSetup();
app.MapMfaDisable(logger);
app.MapConfirmEmail(logger);
app.MapLogoutAll(logger);
app.MapRefresh(logger);
app.MapIntrospect(logger);

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
    bool skipDbInit)
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

