using Mrbr.Service.KeyManager.Services;

namespace Mrbr.Service.EncryptionManager.Services;

public interface IEncryptionService {
    IKeyService KeyService { get; }
    string Encrypt(string dataToEncrypt, IEncryptionOptions encryptionOptions);
    string Decrypt(string dataToDecrypt, IEncryptionOptions encryptionOptions);
}
