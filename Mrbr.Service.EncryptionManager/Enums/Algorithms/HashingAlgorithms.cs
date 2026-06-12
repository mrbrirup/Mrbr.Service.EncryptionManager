namespace Mrbr.Service.EncryptionManager.Enums.Algorithms;

public enum HashingAlgorithms {
    MD5 = 0,         // Message Digest 5 - Old, broken hashing tool; do not use
    SHA0 = 1,        // Secure Hash Algorithm 0 - Obsolete hashing tool with design flaws; do not use
    SHA1 = 2,        // Secure Hash Algorithm 1 - Legacy hashing tool; no longer secure
    SHA224 = 3,      // Secure Hash Algorithm 2 (224-bit) - Smaller variant of SHA-2 hashing
    SHA256 = 4,      // Secure Hash Algorithm 2 (256-bit) - Industry standard hashing tool
    SHA384 = 5,      // Secure Hash Algorithm 2 (384-bit) - High-strength hashing tool
    SHA512 = 6,      // Secure Hash Algorithm 2 (512-bit) - Strongest SHA-2 hashing tool, fast on 64-bit CPUs
    SHA512_224 = 7,  // Secure Hash Algorithm 2 (Truncated to 224 bits) - Fast, secure hashing with shorter output
    SHA512_256 = 8,  // Secure Hash Algorithm 2 (Truncated to 256 bits) - Fast, secure hashing; resists length attacks
    SHA3_224 = 9,    // Secure Hash Algorithm 3 (224-bit) - Next-gen hashing with a new math structure
    SHA3_256 = 10,   // Secure Hash Algorithm 3 (256-bit) - Next-gen standard hashing tool
    SHA3_384 = 11,   // Secure Hash Algorithm 3 (384-bit) - High-strength next-gen hashing tool
    SHA3_512 = 12,   // Secure Hash Algorithm 3 (512-bit) - Strongest next-gen hashing tool
    SHAKE128 = 13,   // Secure Hash Algorithm Keccak (128-bit strength) - Variable-length output hashing function
    SHAKE256 = 14,   // Secure Hash Algorithm Keccak (256-bit strength) - Stronger variable-length output hashing function
    BLAKE3 = 15      // BLAKE3 - Ultra-fast, highly secure modern hashing tool optimized for multi-core CPUs
}
