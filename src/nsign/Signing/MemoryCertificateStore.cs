using System.Security.Cryptography.X509Certificates;

namespace NSign.Signing;

internal sealed class MemoryCertificateStore : IDisposable
{
    private IntPtr _handle;

    private MemoryCertificateStore(IntPtr handle) => _handle = handle;

    public IntPtr Handle => _handle;

    public static MemoryCertificateStore Create()
    {
        var handle = Native.CertOpenStore(
            new IntPtr(Native.CERT_STORE_PROV_MEMORY),
            CertEncodingType.NONE,
            IntPtr.Zero,
            CertOpenStoreFlags.NONE,
            IntPtr.Zero);
        if (handle == IntPtr.Zero)
            throw new InvalidOperationException("CertOpenStore(Memory) failed.");

        return new MemoryCertificateStore(handle);
    }

    public void Add(X509Certificate2 certificate)
    {
        if (!Native.CertAddCertificateContextToStore(_handle, certificate.Handle, Native.CERT_STORE_ADD_ALWAYS, IntPtr.Zero))
            throw new InvalidOperationException("CertAddCertificateContextToStore failed.");
    }

    public void Dispose()
    {
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }

    ~MemoryCertificateStore()
    {
        Dispose(disposing: false);
    }

    private void Dispose(bool disposing)
    {
        _ = disposing;
        if (_handle == IntPtr.Zero)
            return;
        Native.CertCloseStore(_handle, CertCloseStoreFlags.NONE);
        _handle = IntPtr.Zero;
    }
}
