using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace NSign.Credentials;

/// <summary>
/// Stores the token PIN as a per-user generic Windows credential.
/// <c>CRED_PERSIST_LOCAL_MACHINE</c> keeps it across later logon sessions of
/// the same Windows user on this computer. Other users cannot read it.
/// </summary>
internal static class CredentialStore
{
    private const uint CredTypeGeneric = 1;
    private const uint CredPersistLocalMachine = 2;
    private const int ErrorNotFound = 1168;

    public static bool TryReadPin(out PinSecret pin)
    {
        pin = new PinSecret([]);
        if (!CredReadW(Defaults.CredentialTarget, CredTypeGeneric, 0, out var credPtr))
        {
            var error = Marshal.GetLastPInvokeError();
            if (error == ErrorNotFound)
                return false;
            throw new Win32Exception(error);
        }

        try
        {
            var cred = Marshal.PtrToStructure<CREDENTIALW>(credPtr);
            if (cred.CredentialBlob == IntPtr.Zero || cred.CredentialBlobSize == 0)
                return false;

            var charCount = (int)(cred.CredentialBlobSize / sizeof(char));
            var chars = new char[charCount];
            Marshal.Copy(cred.CredentialBlob, chars, 0, charCount);

            var len = chars.Length;
            while (len > 0 && chars[len - 1] == '\0')
                len--;

            if (len == 0)
            {
                CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(chars.AsSpan()));
                return false;
            }

            if (len != chars.Length)
            {
                var trimmed = chars.AsSpan(0, len).ToArray();
                CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(chars.AsSpan()));
                chars = trimmed;
            }

            pin.Dispose();
            pin = new PinSecret(chars);
            return true;
        }
        finally
        {
            CredFree(credPtr);
        }
    }

    public static void WritePin(ReadOnlySpan<char> pin)
    {
        var byteCount = Encoding.Unicode.GetByteCount(pin);
        var blob = new byte[byteCount];
        Encoding.Unicode.GetBytes(pin, blob);

        var targetPtr = Marshal.StringToHGlobalUni(Defaults.CredentialTarget);
        var blobPtr = Marshal.AllocHGlobal(blob.Length);
        try
        {
            Marshal.Copy(blob, 0, blobPtr, blob.Length);
            var cred = new CREDENTIALW
            {
                Type = CredTypeGeneric,
                TargetName = targetPtr,
                CredentialBlobSize = (uint)blob.Length,
                CredentialBlob = blobPtr,
                Persist = CredPersistLocalMachine,
                UserName = targetPtr
            };

            if (!CredWriteW(ref cred, 0))
            {
                var error = Marshal.GetLastPInvokeError();
                throw new Win32Exception(error, $"CredWriteW failed (0x{error:X8}).");
            }
        }
        finally
        {
            if (blobPtr != IntPtr.Zero)
            {
                unsafe
                {
                    new Span<byte>((void*)blobPtr, blob.Length).Clear();
                }

                Marshal.FreeHGlobal(blobPtr);
            }

            CryptographicOperations.ZeroMemory(blob);
            Marshal.FreeHGlobal(targetPtr);
        }
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredReadW(string targetName, uint type, uint flags, out IntPtr credential);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredWriteW(ref CREDENTIALW credential, uint flags);

    [DllImport("advapi32.dll")]
    private static extern void CredFree(IntPtr buffer);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CREDENTIALW
    {
        public uint Flags;
        public uint Type;
        public IntPtr TargetName;
        public IntPtr Comment;
        public long LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint Persist;
        public uint AttributeCount;
        public IntPtr Attributes;
        public IntPtr TargetAlias;
        public IntPtr UserName;
    }
}
