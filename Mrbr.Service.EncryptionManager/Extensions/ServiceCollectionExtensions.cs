using Microsoft.Extensions.DependencyInjection;
using Mrbr.Service.EncryptionManager.Services;

namespace Mrbr.Service.EncryptionManager.Extensions;

/// <summary>
/// Dependency injection registration helpers for EncryptionManager services.
/// </summary>
public static class ServiceCollectionExtensions {
    /// <summary>
    /// Registers EncryptionManager services.
    /// </summary>
    /// <param name="services">The service collection to register with.</param>
    /// <returns>The same service collection for chaining.</returns>
    /// <remarks>Consumers must register KeyManager's IKeyService separately.</remarks>
    public static IServiceCollection AddEncryptionManager(this IServiceCollection services) {
        ArgumentNullException.ThrowIfNull(services);

        services.AddSingleton<ICryptographicService, CryptographicService>();
        return services;
    }
}
