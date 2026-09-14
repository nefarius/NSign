using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace NSign.Signing;

internal sealed record CertRow(string Thumbprint, string Subject, DateTime NotAfter, string Provider, string KeyName);

internal static class CertificateResolver
{
    public static X509Certificate2 Resolve(string? thumbprint, string? subject)
    {
        using var store = OpenMy();
        var candidates = store.Certificates.OfType<X509Certificate2>().ToList();

        X509Certificate2? match = null;
        if (!string.IsNullOrWhiteSpace(thumbprint))
        {
            var want = NormalizeThumbprint(thumbprint);
            match = candidates.FirstOrDefault(c =>
                string.Equals(NormalizeThumbprint(c.Thumbprint), want, StringComparison.OrdinalIgnoreCase));
            if (match is null)
                throw new InvalidOperationException($"No certificate with thumbprint {thumbprint} in CurrentUser\\My.");
        }
        else if (!string.IsNullOrWhiteSpace(subject))
        {
            match = candidates
                .Where(c => c.Subject.Contains(subject, StringComparison.OrdinalIgnoreCase))
                .Where(IsCodeSigning)
                .Where(c => c.HasPrivateKey)
                .OrderByDescending(c => c.NotAfter)
                .FirstOrDefault();
            if (match is null)
                throw new InvalidOperationException(
                    $"No CurrentUser\\My code-signing certificate matches subject '{subject}'.");
        }
        else
        {
            match = candidates.FirstOrDefault(c =>
                string.Equals(NormalizeThumbprint(c.Thumbprint), Defaults.DefaultThumbprint,
                    StringComparison.OrdinalIgnoreCase));
            if (match is null)
                throw new InvalidOperationException(
                    $"No default certificate ({Defaults.DefaultThumbprint}) in CurrentUser\\My. Pass /sha1 or /n.");
        }

        return new X509Certificate2(match);
    }

    public static IReadOnlyList<CertRow> ListEligible()
    {
        using var store = OpenMy();
        var rows = new List<CertRow>();
        foreach (var cert in store.Certificates)
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

    private static X509Store OpenMy()
    {
        var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
        return store;
    }

    private static bool IsCodeSigning(X509Certificate2 cert)
    {
        foreach (var ext in cert.Extensions)
        {
            if (ext is X509EnhancedKeyUsageExtension eku)
            {
                return eku.EnhancedKeyUsages.OfType<System.Security.Cryptography.Oid>()
                    .Any(o => o.Value == Defaults.CodeSigningEku);
            }
        }

        // No EKU extension means the cert is unconstrained.
        return true;
    }

    private static string NormalizeThumbprint(string? value)
        => (value ?? "").Replace(" ", "", StringComparison.Ordinal).ToUpperInvariant();
}
