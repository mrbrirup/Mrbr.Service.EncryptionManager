// Add DI for encryption manager and test encryption and decryption functionality

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Mrbr.Service.EncryptionManager.Services;
using Mrbr.Service.EncryptionManager.Services.Encryption;
using Mrbr.Service.KeyManager.Compression;
using Mrbr.Service.KeyManager.Configuration;
using Mrbr.Service.KeyManager.Services;


HostApplicationBuilder builder = Host.CreateApplicationBuilder(args);
IConfiguration config = new ConfigurationBuilder()
    .SetBasePath(Directory.GetCurrentDirectory())
    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
    .AddJsonFile("appsettings.keyservice.json", optional: false, reloadOnChange: true)
    .Build();
var testName = config["TestSection"] ?? "DefaultTest";
// Read nested sections
var keySize = config["Encryption:KeySize"];
//var keyServiceSection = config.GetSection("KeyService");
var services = builder.Services;
services
    .Configure<KeyServiceConfig>(keyServiceSection => {
        config.GetSection(nameof(KeyService)).Bind(keyServiceSection);
    });
//.AddOptions<KeyServiceConfig>()
//.Bind(builder.Configuration.GetSection(nameof(KeyService)));

services.AddSingleton<KeyServiceOptions>();
services.AddSingleton<IKeyService, KeyService>();

//builder.Services.AddSingleton<IKeyService, KeyService>();
builder.Services.AddSingleton<IEncryptionService, AesEncryptionService>();

using IHost host = builder.Build();
KeyServiceOptions keyServiceOptions = host.Services.GetRequiredService<KeyServiceOptions>();
KeyService keyService = host.Services.GetRequiredService<IKeyService>() as KeyService ?? throw new InvalidOperationException("Failed to resolve KeyService.");

var key1 = 1;
var startPostion = 1056;
var length = 253;

var result = BitPacker.BlockKeyPack((uint)key1, (uint)startPostion, (uint)length);
BitPacker.BlockKeyUnpack(result, out var unpackedKey, out var unpackedStart, out var unpackedLength);


var key = keyService.GenerateKey(out var keyResult);
Console.WriteLine("KeyResult:");
Console.WriteLine(keyResult);

Console.WriteLine("Key:");
Console.WriteLine(key.ToString());

var sourceText = keyService.GetKey(keyResult);
Console.WriteLine("Source Text:");
Console.WriteLine(sourceText);
Console.ReadKey();