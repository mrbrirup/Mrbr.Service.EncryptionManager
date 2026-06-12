# Mrbr.Service.EncryptionManager

A robust .NET encryption service library that provides symmetric and asymmetric encryption capabilities, along with hashing functionality. This library is designed to simplify cryptographic operations in your applications.

## Features

- **Symmetric Encryption**: AES-based encryption with multiple key sizes and modes
- **Asymmetric Encryption**: Support for RSA and other asymmetric algorithms
- **Hashing**: Multiple hashing algorithms for secure data integrity verification
- **Integration**: Seamless integration with Mrbr.Service.KeyManager for key management
- **.NET 11 Native**: Built for modern .NET with implicit usings and nullable reference types enabled

## Installation

Install via NuGet:

```bash
dotnet add package Mrbr.Service.EncryptionManager
```

Or via Package Manager:

```
Install-Package Mrbr.Service.EncryptionManager
```

## Quick Start

### Using AES Encryption

```csharp
using Mrbr.Service.EncryptionManager.Services.Encryption;
using Mrbr.Service.KeyManager.Services;

// Create a key service and encryption service
IKeyService keyService = new YourKeyService();
var encryptionService = new AesEncryptionService(keyService);

// Encrypt data
var encryptionOptions = new YourEncryptionOptions();
string plainText = "Sensitive data";
string encrypted = encryptionService.Encrypt(plainText, encryptionOptions);

// Decrypt data
string decrypted = encryptionService.Decrypt(encrypted, encryptionOptions);
```

## Supported Algorithms

### Symmetric Algorithms
- AES (Advanced Encryption Standard)

### Asymmetric Algorithms
- RSA
- ECDSA
- DSA

### Hashing Algorithms
- SHA256
- SHA512
- MD5
- SHA1

## Dependencies

- **Mrbr.Service.KeyManager** (v1.0.1+) - For key management operations
- **Mrbr.SourceGenerators.Common** (v1.0.0+) - For source code generation

## Architecture

The library follows a service-oriented architecture with the following key components:

- **IEncryptionService**: Core interface for encryption/decryption operations
- **IEncryptionOptions**: Configuration interface for encryption parameters
- **Algorithm Enums**: Type-safe algorithm selection (AsymmetricAlgorithms, SymmetricEncryptionAlgorithms, HashingAlgorithms)
- **Service Implementations**: Ready-to-use encryption service implementations

## Version

Current version: **1.0.2**

## Requirements

- .NET 11.0 or higher
- A key management service (from Mrbr.Service.KeyManager)

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues on GitHub.

## License

Please refer to the LICENSE file in the repository for licensing information.

## Support

For issues, questions, or contributions, please visit the [GitHub repository](https://github.com/mrbrirup/Mrbr.Service.EncryptionManager).