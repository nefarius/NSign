using System.Security.Cryptography;
using System.Text;

using NSign.Signing;

namespace NSign.Tests;

public sealed class NativeHashMappingTests
{
    [Theory]
    [InlineData("SHA1", 0x00008004u, "1.3.14.3.2.26")]
    [InlineData("SHA256", 0x0000800cu, "2.16.840.1.101.3.4.2.1")]
    [InlineData("SHA384", 0x0000800du, "2.16.840.1.101.3.4.2.2")]
    [InlineData("SHA512", 0x0000800eu, "2.16.840.1.101.3.4.2.3")]
    public void MapsHashAlgorithmsToAlgIdAndOid(string name, uint algId, string oid)
    {
        var algorithm = new HashAlgorithmName(name);
        Assert.Equal(algId, Native.HashAlgorithmToAlgId(algorithm));

        var mapped = Native.HashAlgorithmToOidAsciiTerminated(algorithm);
        Assert.Equal(oid + "\0", Encoding.ASCII.GetString(mapped));
    }

    [Fact]
    public void RejectsUnknownHashAlgorithm()
    {
        var algorithm = new HashAlgorithmName("MD5");
        Assert.Throws<NotSupportedException>(() => Native.HashAlgorithmToAlgId(algorithm));
        Assert.Throws<NotSupportedException>(() => Native.HashAlgorithmToOidAsciiTerminated(algorithm));
    }
}
