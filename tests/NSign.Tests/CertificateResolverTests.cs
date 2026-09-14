using NSign.Signing;

namespace NSign.Tests;

public sealed class CertificateResolverTests
{
    [Fact]
    public void NormalizeThumbprint_StripsSpacesAndUppercases()
    {
        Assert.Equal("AABBCC", CertificateResolver.NormalizeThumbprint("aa bb cc"));
        Assert.Equal("", CertificateResolver.NormalizeThumbprint(null));
    }

    [Fact]
    public void IsCodeSigning_RequiresCodeSigningEku()
    {
        using var signing = TestCertificates.Create("CN=Code", codeSigning: true);
        using var server = TestCertificates.Create("CN=Web", codeSigning: false);
        using var unconstrained = TestCertificates.CreateWithoutEku("CN=Any");

        Assert.True(CertificateResolver.IsCodeSigning(signing));
        Assert.False(CertificateResolver.IsCodeSigning(server));
        Assert.False(CertificateResolver.IsCodeSigning(unconstrained));
    }

    [Fact]
    public void SelectCertificate_ThumbprintRequiresCodeSigningAndUsableKey()
    {
        using var signing = TestCertificates.Create("CN=Token", codeSigning: true);
        using var other = TestCertificates.Create("CN=Other", codeSigning: false);
        var certs = new[] { signing, other };

        var selected = CertificateResolver.SelectCertificate(
            certs,
            signing.Thumbprint,
            subject: null,
            _ => true);
        Assert.Same(signing, selected);

        Assert.Throws<InvalidOperationException>(() =>
            CertificateResolver.SelectCertificate(certs, other.Thumbprint, subject: null, _ => true));
        Assert.Throws<InvalidOperationException>(() =>
            CertificateResolver.SelectCertificate(certs, signing.Thumbprint, subject: null, _ => false));
    }

    [Fact]
    public void SelectCertificate_SubjectPicksNewestCodeSigningMatch()
    {
        using var older = TestCertificates.Create("CN=Acme Signer", codeSigning: true, DateTimeOffset.UtcNow.AddDays(10));
        using var newer = TestCertificates.Create("CN=Acme Signer", codeSigning: true, DateTimeOffset.UtcNow.AddDays(40));
        using var unrelated = TestCertificates.Create("CN=Other", codeSigning: true);

        var selected = CertificateResolver.SelectCertificate(
            [older, newer, unrelated],
            thumbprint: null,
            subject: "Acme",
            static _ => true);

        Assert.Same(newer, selected);
    }

    [Fact]
    public void SelectCertificate_RequiresSelector()
    {
        using var cert = TestCertificates.Create("CN=Token", codeSigning: true);
        var ex = Assert.Throws<InvalidOperationException>(() =>
            CertificateResolver.SelectCertificate([cert], thumbprint: null, subject: null, static _ => true));
        Assert.Contains("/sha1", ex.Message);
    }
}
