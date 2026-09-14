using System.Security.Cryptography;

namespace NSign.Signing;

internal static class HashAlgorithms
{
    public static HashAlgorithmName Parse(string? name, string what)
    {
        return (name ?? "sha256").Trim().ToLowerInvariant() switch
        {
            "sha1" or "sha-1" => HashAlgorithmName.SHA1,
            "sha256" or "sha-256" => HashAlgorithmName.SHA256,
            "sha384" or "sha-384" => HashAlgorithmName.SHA384,
            "sha512" or "sha-512" => HashAlgorithmName.SHA512,
            _ => throw new InvalidOperationException($"Unsupported {what} algorithm '{name}'.")
        };
    }
}
