using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SecureAuthMinimalApi.Data;
using SecureAuthMinimalApi.Models;

namespace SecureAuthMinimalApi.Services;

/// <summary>
/// Background service che elimina periodicamente record scaduti/revocati.
/// </summary>
public sealed class ExpiredCleanupService : BackgroundService
{
    private readonly CleanupOptions _options;
    private readonly SessionRepository _sessions;
    private readonly RefreshTokenRepository _refreshTokens;
    private readonly MfaChallengeRepository _challenges;
    private readonly ILogger<ExpiredCleanupService> _logger;

    /// <summary>
    /// Inietta dipendenze e opzioni per il cleanup periodico.
    /// </summary>
    public ExpiredCleanupService(
        IOptions<CleanupOptions> options,
        SessionRepository sessions,
        RefreshTokenRepository refreshTokens,
        MfaChallengeRepository challenges,
        ILogger<ExpiredCleanupService> logger)
    {
        _options = options.Value;
        _sessions = sessions;
        _refreshTokens = refreshTokens;
        _challenges = challenges;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_options.Enabled)
        {
            _logger.LogInformation("ExpiredCleanupService disabilitato via configurazione");
            return;
        }

        var intervalSeconds = _options.IntervalSeconds > 0 ? _options.IntervalSeconds : 300;
        var batchSize = _options.BatchSize > 0 ? _options.BatchSize : 200;
        var maxIterations = _options.MaxIterationsPerRun.GetValueOrDefault(3);
        if (maxIterations <= 0)
        {
            maxIterations = 1;
        }

        _logger.LogInformation(
            "ExpiredCleanupService avviato: intervalSeconds={Interval}, batchSize={Batch}, maxIterations={MaxIterations}",
            intervalSeconds,
            batchSize,
            maxIterations);

        var delay = TimeSpan.FromSeconds(intervalSeconds);
        while (!stoppingToken.IsCancellationRequested)
        {
            await RunOnceAsync(batchSize, maxIterations, stoppingToken);
            try
            {
                await Task.Delay(delay, stoppingToken);
            }
            catch (TaskCanceledException)
            {
                break;
            }
        }
    }

    private async Task RunOnceAsync(int batchSize, int maxIterations, CancellationToken ct)
    {
        try
        {
            var nowIso = DateTime.UtcNow.ToString("O");
            var totalSessions = 0;
            var totalRefresh = 0;
            var totalChallenges = 0;

            for (var i = 0; i < maxIterations && !ct.IsCancellationRequested; i++)
            {
                var deletedSessions = await _sessions.DeleteExpiredAsync(nowIso, batchSize, ct);
                var deletedRefresh = await _refreshTokens.DeleteExpiredAsync(nowIso, batchSize, ct);
                var deletedChallenges = await _challenges.DeleteExpiredAsync(nowIso, batchSize, ct);

                totalSessions += deletedSessions;
                totalRefresh += deletedRefresh;
                totalChallenges += deletedChallenges;

                var deletedThisBatch = deletedSessions + deletedRefresh + deletedChallenges;
                if (deletedThisBatch < batchSize)
                {
                    break;
                }
            }

            if (totalSessions + totalRefresh + totalChallenges > 0)
            {
                _logger.LogInformation(
                    "Cleanup completato: sessions={Sessions}, refresh={Refresh}, challenges={Challenges}",
                    totalSessions,
                    totalRefresh,
                    totalChallenges);
            }
            else
            {
                _logger.LogDebug("Cleanup: nessun record scaduto da rimuovere");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Errore durante il cleanup dei record scaduti");
        }
    }
}
