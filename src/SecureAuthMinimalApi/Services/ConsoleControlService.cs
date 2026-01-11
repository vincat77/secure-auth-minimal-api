namespace SecureAuthMinimalApi.Services;

/// <summary>
/// Gestisce i controlli da console (pausa/ripresa, arresto) durante l'esecuzione self-hosted.
/// </summary>
public sealed class ConsoleControlService
{
    private readonly PauseController _pauseController;
    private readonly ILogger<ConsoleControlService> _logger;

    public ConsoleControlService(PauseController pauseController, ILogger<ConsoleControlService> logger)
    {
        _pauseController = pauseController;
        _logger = logger;
    }

    /// <summary>
    /// Avvia il loop di gestione console. Se l'input è reindirizzato, registra un warning e termina subito.
    /// </summary>
    public Task RunAsync(CancellationTokenSource shutdownCts, WebApplication app)
    {
        if (Console.IsInputRedirected)
        {
            _logger.LogWarning("Input console non disponibile: arresto con Ctrl+C/TERM. Controlli P/S disabilitati.");
            return Task.CompletedTask;
        }

        return Task.Run(async () =>
        {
            _logger.LogInformation("Controlli console: premi 'P' per pausa/ripresa, 'S' per arresto sicuro.");
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
                    _logger.LogInformation("Arresto richiesto da console (S).");
                    shutdownCts.Cancel();
                    app.Lifetime.StopApplication();
                    break;
                }

                if (key.Key == ConsoleKey.P)
                {
                    var isPausedNow = _pauseController.Toggle();
                    _logger.LogWarning(isPausedNow
                        ? "Applicazione messa in pausa: risposte 503 finché non viene ripresa."
                        : "Pausa rimossa: ripresa gestione richieste.");
                }
            }
        }, shutdownCts.Token);
    }
}
