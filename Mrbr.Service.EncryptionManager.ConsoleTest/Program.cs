using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Mrbr.Service.EncryptionManager.Extensions;
using Mrbr.Service.EncryptionManager.Services;
using Mrbr.Service.KeyManager.Configuration;
using Mrbr.Service.KeyManager.Services;

HostApplicationBuilder builder = Host.CreateApplicationBuilder(args);
IConfiguration config = new ConfigurationBuilder()
    .SetBasePath(AppContext.BaseDirectory)
    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
    .AddJsonFile("appsettings.keyservice.json", optional: false, reloadOnChange: true)
    .Build();

var services = builder.Services;
services.Configure<KeyServiceConfig>(keyServiceSection => {
    config.GetSection(nameof(KeyService)).Bind(keyServiceSection);
});

services.AddSingleton<KeyServiceOptions>();
services.AddSingleton<IKeyService, KeyService>();
services.AddEncryptionManager();

using IHost host = builder.Build();
var encryptionService = host.Services.GetRequiredService<ICryptographicService>();

const string plainText = "Sensitive data";
var encrypted = encryptionService.EncryptText(plainText);
var decrypted = encryptionService.DecryptText(encrypted);

Console.WriteLine("Encrypted:");
Console.WriteLine(encrypted);

Console.WriteLine("Decrypted:");
Console.WriteLine(decrypted);
