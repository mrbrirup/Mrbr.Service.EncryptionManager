using Microsoft.Extensions.Options;
using Mrbr.Service.KeyManager.Configuration;
using Mrbr.Service.KeyManager.Services;
using System.Reflection;
using System.Security.Cryptography;

[assembly: CollectionBehavior(DisableTestParallelization = true)]
namespace Mrbr.Service.EncryptionManager.Tests;

// Test-only process isolation. Production must never reset or overwrite the shared registry.
internal sealed class KeyManagerTestEnvironment : IDisposable {
    private readonly string directory = Path.Combine(Path.GetTempPath(), "mrbr-encryption-tests-" + Guid.NewGuid().ToString("N"));
    internal KeyServiceConfig Config { get; } = new();
    internal KeyServiceOptions Options { get; private set; } = null!;
    internal KeyService Create(byte[] ids, KeyType type = KeyType.Block) {
        ResetRegistry();
        foreach (byte id in ids) {
            var entry = KeyServiceEntry.FromBytes(id, RandomNumberGenerator.GetBytes(4096), "565342976", type);
            if (type == KeyType.Matrix) entry.MatrixSettings = new() { Width = 16, Height = 16, Depth = 16 };
            Config.Add(entry);
        }
        Options = new( Microsoft.Extensions.Options.Options.Create(Config), new KeyValidationOptions {
            ApplicationId = "EncryptionTests", HistoryDirectory = directory, AllowInitialEnrollment = true
        });
        return new KeyService(Options);
    }
    internal void SetState(KeySourceState state) {
        Config[0].State = state;
        Options.ApplyConfiguration(Config);
    }
    private static void ResetRegistry() {
        foreach (string field in new[] { "_records", "_application", "_directory", "_lastHistoryHash" })
            typeof(KeyServiceOptions).GetField(field, BindingFlags.NonPublic | BindingFlags.Static)!.SetValue(null, null);
        while (KeyConfigurationAudit.TryDequeue(out _)) { }
    }
    public void Dispose() {
        ResetRegistry();
        if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
    }
}
