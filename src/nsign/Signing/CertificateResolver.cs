using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace NSign.Signing;

internal sealed record CertRow(string Thumbprint, string Subject, DateTime NotAfter, string Provider, string KeyName);

internal static class CertificateResolver
{
    public static X509Certificate2 Resolve(string? thumbprint, string? subject)
    {
        using var store = OpenMy();
        var certificates = store.Certificates;
        try
        {
            var match = SelectCertificate(
                certificates.OfType<X509Certificate2>(),
                thumbprint,
                subject,
                HasUsableRsaCngKey);
            return new X509Certificate2(match);
        }
        finally
        {
            DisposeCertificates(certificates);
        }
    }

    public static IReadOnlyList<CertRow> ListEligible()
    {
        using var store = OpenMy();
        var certificates = store.Certificates;
        try
        {
            var rows = new List<CertRow>();
            foreach (X509Certificate2 cert in certificates)
            {
                if (!cert.HasPrivateKey || !IsCodeSigning(cert))
                    continue;

                var provider = "(unknown)";
                var keyName = "";
                try
                {
                    using var rsa = cert.GetRSAPrivateKey();
                    if (rsa is RSACng cng)
                    {
                        provider = cng.Key.Provider?.Provider ?? "(unknown)";
                        keyName = cng.Key.KeyName ?? "";
                    }
                    else if (rsa is not null)
                    {
                        provider = rsa.GetType().Name;
                    }
                }
                catch (CryptographicException)
                {
                    provider = "(key unavailable)";
                }

                rows.Add(new CertRow(cert.Thumbprint ?? "", cert.Subject, cert.NotAfter, provider, keyName));
            }

            return rows
                .OrderByDescending(r => string.Equals(r.Provider, Defaults.SafeNetKsp, StringComparison.OrdinalIgnoreCase))
                .ThenByDescending(r => r.NotAfter)
                .ToList();
        }
        finally
        {
            DisposeCertificates(certificates);
        }
    }

    internal static X509Certificate2 SelectCertificate(
        IEnumerable<X509Certificate2> candidates,
        string? thumbprint,
        string? subject,
        Func<X509Certificate2, bool> keyUsable)
    {
        var snapshot = candidates as IList<X509Certificate2> ?? candidates.ToList();

        if (!string.IsNullOrWhiteSpace(thumbprint))
        {
            var want = NormalizeThumbprint(thumbprint);
            var match = snapshot.FirstOrDefault(c =>
                string.Equals(NormalizeThumbprint(c.Thumbprint), want, StringComparison.OrdinalIgnoreCase)
                && IsCodeSigning(c)
                && keyUsable(c));
            if (match is null)
                throw new InvalidOperationException(
                    $"No certificate with thumbprint {thumbprint} and a usable RSA CNG private key in CurrentUser\\My.");
            return match;
        }

        if (!string.IsNullOrWhiteSpace(subject))
        {
            var match = snapshot
                .Where(c => c.Subject.Contains(subject, StringComparison.OrdinalIgnoreCase))
                .Where(IsCodeSigning)
                .Where(c => c.HasPrivateKey)
                .Where(keyUsable)
                .OrderByDescending(c => c.NotAfter)
                .FirstOrDefault();
            if (match is null)
                throw new InvalidOperationException(
                    $"No CurrentUser\\My code-signing certificate matches subject '{subject}'.");
            return match;
        }

        throw new InvalidOperationException("Pass /sha1 <thumbprint> or /n <subject> to select a certificate.");
    }

    internal static bool IsCodeSigning(X509Certificate2 cert)
    {
        foreach (var ext in cert.Extensions)
        {
            if (ext is X509EnhancedKeyUsageExtension eku)
            {
                return eku.EnhancedKeyUsages.OfType<Oid>()
                    .Any(o => o.Value == Defaults.CodeSigningEku);
            }
        }

        return false;
    }

    internal static string NormalizeThumbprint(string? value)
        => (value ?? "").Replace(" ", "", StringComparison.Ordinal).ToUpperInvariant();

    internal static bool HasUsableRsaCngKey(X509Certificate2 cert)
    {
        if (!cert.HasPrivateKey)
            return false;

        try
        {
            using var rsa = cert.GetRSAPrivateKey();
            return rsa is RSACng;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static X509Store OpenMy()
    {
        var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
        return store;
    }

    private static void DisposeCertificates(X509Certificate2Collection certificates)
    {
        foreach (X509Certificate2 cert in certificates)
            cert.Dispose();
    }
}
