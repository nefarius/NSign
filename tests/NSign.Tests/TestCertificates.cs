using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace NSign.Tests;

internal static class TestCertificates
{
    public static X509Certificate2 Create(string subject, bool codeSigning, DateTimeOffset? notAfter = null)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var oid = codeSigning ? Defaults.CodeSigningEku : "1.3.6.1.5.5.7.3.1";
        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(new OidCollection { new Oid(oid) }, critical: false));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), notAfter ?? DateTimeOffset.UtcNow.AddDays(30));
    }

    public static X509Certificate2 CreateWithoutEku(string subject)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
    }
}
