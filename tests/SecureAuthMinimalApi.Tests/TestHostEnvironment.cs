using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;

namespace SecureAuthMinimalApi.Tests;

/// <summary>
/// Implementazione minimale di IHostEnvironment per i test.
/// </summary>
internal sealed class TestEnv : IHostEnvironment
{
    public string EnvironmentName { get; set; } = Environments.Development;
    public string ApplicationName { get; set; } = "Tests";
    public string ContentRootPath { get; set; } = Path.GetTempPath();
    public IFileProvider ContentRootFileProvider { get; set; }

    public TestEnv()
    {
        ContentRootFileProvider = new PhysicalFileProvider(ContentRootPath);
    }
}
