using System.Security.Cryptography;

namespace NSign.Signing;

internal sealed class SignOptions
{
    public bool Verbose { get; init; }
    public bool AppendSignature { get; init; }
    public string? Thumbprint { get; init; }
    public string? Subject { get; init; }
    public HashAlgorithmName FileDigest { get; init; } = HashAlgorithmName.SHA256;
    public HashAlgorithmName TimestampDigest { get; init; } = HashAlgorithmName.SHA256;
    public string? TimestampUrl { get; init; } = Defaults.DefaultTimestampUrl;
    public string? Description { get; init; }
    public string? DescriptionUrl { get; init; }
    public IReadOnlyList<string> Files { get; init; } = [];
}
