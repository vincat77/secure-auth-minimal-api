# Piano: Logging centralizzato con Serilog

Obiettivo: abilitare log strutturati (file + console) con Serilog, pronti per integrazione centralizzata (Seq/Elastic). Minimizzare impatto funzionale.

## Passi
1) Dipendenze: Serilog.AspNetCore, Serilog.Sinks.File, Serilog.Enrichers.Environment, Serilog.Enrichers.Process, Serilog.Enrichers.Thread (opzionale: Serilog.Sinks.Seq).
2) Config appsettings: sezione Serilog con MinimumLevel, Enrich, WriteTo file (rolling daily) e console; blocco Seq commentato per futuro.
3) Bootstrap: usare builder.Host.UseSerilog(...) in Program.cs, rimuovere LoggerFactory custom e usare ILogger.
4) Validazione: build + dotnet test; avvio manuale per verificare creazione log e output.
