using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace NSign.Credentials;

/// <summary>Holds a PIN in a disposable <c>char[]</c> that is zeroed on dispose.</summary>
internal sealed class PinSecret : IDisposable
{
    private char[]? _chars;

    public PinSecret(char[] chars) => _chars = chars;

    public ReadOnlySpan<char> Span => _chars ?? ReadOnlySpan<char>.Empty;

    public bool IsEmpty => _chars is null || _chars.Length == 0;

    public void Dispose()
    {
        if (_chars is null)
            return;

        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(_chars.AsSpan()));
        _chars = null;
        GC.SuppressFinalize(this);
    }
}
