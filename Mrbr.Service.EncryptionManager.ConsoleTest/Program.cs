using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Mrbr.Service.EncryptionManager.Extensions;
using Mrbr.Service.EncryptionManager.Services;
using Mrbr.Service.KeyManager.Configuration;
using Mrbr.Service.KeyManager.Services;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

// Host-owned enrollment, loading and audit consumption; EncryptionManager only performs cryptographic operations.
string configPath = Path.Combine(AppContext.BaseDirectory, "appsettings.keyservice.json");
string? historyPath = null;
string? generatePath = null;
bool enroll = false;
byte sourceId = 7;
for (int i = 0; i < args.Length; i++) {
    switch (args[i]) {
        case "--enroll": enroll = true; break;
        case "--config" when i + 1 < args.Length: configPath = Path.GetFullPath(args[++i]); break;
        case "--history" when i + 1 < args.Length: historyPath = Path.GetFullPath(args[++i]); break;
        case "--source" when i + 1 < args.Length: sourceId = byte.Parse(args[++i]); break;
        case "--create-demo-config" when i + 1 < args.Length: generatePath = Path.GetFullPath(args[++i]); break;
        default: throw new ArgumentException("Use --enroll, --config PATH, --history PATH, --source ID or --create-demo-config PATH.");
    }
}
var jsonOptions = new JsonSerializerOptions { WriteIndented = true };
jsonOptions.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.CamelCase));
if (generatePath is not null) {
    var entry = KeyServiceEntry.FromBytes(sourceId, RandomNumberGenerator.GetBytes(4096));
    using var output = new FileStream(generatePath, FileMode.CreateNew, FileAccess.Write);
    JsonSerializer.Serialize(output, new { KeyService = new KeyServiceConfig { entry } }, jsonOptions);
    Console.WriteLine("Created a new disposable demo configuration. Never use published demo sources for real data.");
    return;
}

try {
    var builder = Host.CreateApplicationBuilder();
    builder.Services.AddSingleton(new KeyValidationOptions {
        ApplicationId = "EncryptionManagerConsoleDemo", HistoryDirectory = historyPath, AllowInitialEnrollment = enroll
    });
    builder.Services.AddSingleton<IOptions<KeyServiceConfig>>(new FileKeyOptions(configPath));
    builder.Services.AddSingleton<KeyServiceOptions>();
    builder.Services.AddSingleton<IKeyService, KeyService>();
    builder.Services.AddEncryptionManager();
    using IHost host = builder.Build();
    // Resolve before using the application; binding errors are captured inside KeyManager's audit boundary.
    var crypto = host.Services.GetRequiredService<ICryptographicService>();
    const string plainText = "Disposable demo datum";
    string encrypted = crypto.EncryptText(sourceId, plainText);
    if (crypto.DecryptText(encrypted) != plainText) throw new InvalidOperationException("Round-trip failed.");
    Console.WriteLine("Encryption/decryption round-trip succeeded.");
    // A file watcher alone does not accept updates. A host can explicitly call
    // KeyServiceOptions.Reload(() => new FileKeyOptions(configPath).Value) and handle rejection.
} catch (KeyConfigurationException failure) {
    Console.Error.WriteLine($"Configuration rejected: {failure.FailureCode}; attempt {failure.ConfigurationAttemptId}.");
    Environment.ExitCode = 1;
} finally {
    // Demo destination only. Production hosts own durable delivery, retries and alerts.
    while (KeyConfigurationAudit.TryDequeue(out var audit)) Console.WriteLine(JsonSerializer.Serialize(audit, jsonOptions));
}

internal sealed class FileKeyOptions(string path) : IOptions<KeyServiceConfig> {
    public KeyServiceConfig Value {
        get {
            var configuration = new ConfigurationBuilder().AddJsonFile(path, optional: false, reloadOnChange: false).Build();
            using var lifetime = configuration as IDisposable;
            return configuration.GetSection("KeyService").Get<KeyServiceConfig>(b => b.ErrorOnUnknownConfiguration = true)
                ?? throw new InvalidOperationException("KeyService section is required.");
        }
    }
}
