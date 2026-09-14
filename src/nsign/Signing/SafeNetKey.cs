using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace NSign.Signing;

internal sealed class SafeNetKey : IDisposable
{
    private readonly RSACng _rsa;
    private readonly X509Certificate2 _certificate;

    private SafeNetKey(X509Certificate2 certificate, RSACng rsa)
    {
        _certificate = certificate;
        _rsa = rsa;
    }

    public X509Certificate2 Certificate => _certificate;

    public static SafeNetKey Open(X509Certificate2 certificate, string pin)
    {
        var rsa = certificate.GetRSAPrivateKey() as RSACng
            ?? throw new InvalidOperationException(
                "Certificate private key is not an RSA CNG key (SafeNet KSP expected).");

        var provider = rsa.Key.Provider?.Provider ?? "(unknown)";
        if (!string.Equals(provider, Defaults.SafeNetKsp, StringComparison.OrdinalIgnoreCase))
        {
            Console.Error.WriteLine($"Warning: key provider is '{provider}', expected '{Defaults.SafeNetKsp}'.");
        }

        try
        {
            InjectPin(rsa.Key, pin);
        }
        catch (CryptographicException ex)
        {
            rsa.Dispose();
            throw new TokenException(ex.HResult, TokenStatus.Describe(ex.HResult));
        }

        return new SafeNetKey(certificate, rsa);
    }

    public unsafe byte[] SignHash(byte[] digest, HashAlgorithmName hashAlgorithm)
    {
        var alg = (hashAlgorithm.Name ?? "SHA256") + "\0";
        fixed (char* pAlg = alg)
        {
            var padding = new BCRYPT_PKCS1_PADDING_INFO { pszAlgId = (IntPtr)pAlg };
            var flags = Native.NCRYPT_PAD_PKCS1_FLAG | Native.NCRYPT_SILENT_FLAG;
            var signature = new byte[Math.Max(64, _rsa.KeySize / 8)];

            var status = Native.NCryptSignHash(
                _rsa.Key.Handle,
                (IntPtr)(&padding),
                digest,
                digest.Length,
                signature,
                signature.Length,
                out var size,
                flags);
            if (status != 0)
                throw new TokenException(status, TokenStatus.Describe(status));

            if (size != signature.Length)
                Array.Resize(ref signature, size);

            return signature;
        }
    }

    public void Dispose()
    {
        _rsa.Dispose();
    }

    private static void InjectPin(CngKey key, string pin)
    {
        var bytes = Encoding.Unicode.GetBytes(pin + "\0");
        key.SetProperty(new CngProperty("SmartCardPin", bytes, CngPropertyOptions.None));
        CryptographicOperations.ZeroMemory(bytes);
    }
}
