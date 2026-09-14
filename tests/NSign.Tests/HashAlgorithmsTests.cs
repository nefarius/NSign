using System.Security.Cryptography;

using NSign.Signing;

namespace NSign.Tests;

public sealed class HashAlgorithmsTests
{
    [Theory]
    [InlineData(null, "SHA256")]
    [InlineData("sha256", "SHA256")]
    [InlineData("SHA-256", "SHA256")]
    [InlineData("sha1", "SHA1")]
    [InlineData("sha-1", "SHA1")]
    [InlineData("sha384", "SHA384")]
    [InlineData("sha512", "SHA512")]
    public void Parse_AcceptsKnownAliases(string? name, string expected)
    {
        Assert.Equal(new HashAlgorithmName(expected), HashAlgorithms.Parse(name, "file digest"));
    }

    [Fact]
    public void Parse_RejectsUnknownAlgorithm()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => HashAlgorithms.Parse("md5", "file digest"));
        Assert.Contains("file digest", ex.Message);
        Assert.Contains("md5", ex.Message);
    }
}
