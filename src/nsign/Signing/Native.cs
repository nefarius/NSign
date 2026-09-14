// Interop layout follows AzureSignTool (MIT),
// Copyright (c) 2017 Kevin Jones and Oren Novotny.
// https://github.com/vcsjones/AzureSignTool
#pragma warning disable IDE1006 // Win32 / AzureSignTool field names
using System.Runtime.InteropServices;
using System.Security.Cryptography;

using Microsoft.Win32.SafeHandles;

namespace NSign.Signing;

internal static class Native
{
    public const int NCRYPT_PAD_PKCS1_FLAG = 0x00000002;
    public const int NCRYPT_SILENT_FLAG = 0x00000040;
    public const uint CERT_STORE_ADD_ALWAYS = 4;
    public const int CERT_STORE_PROV_MEMORY = 2;

    [DllImport("ncrypt.dll")]
    public static extern int NCryptSignHash(
        SafeNCryptKeyHandle hKey,
        IntPtr pPaddingInfo,
        byte[] pbHashValue,
        int cbHashValue,
        byte[]? pbSignature,
        int cbSignature,
        out int pcbResult,
        int dwFlags);

    [DllImport("mssign32.dll", EntryPoint = "SignerSignEx3", CallingConvention = CallingConvention.Winapi)]
    public static extern unsafe int SignerSignEx3(
        SignerSignEx3Flags dwFlags,
        SIGNER_SUBJECT_INFO* pSubjectInfo,
        SIGNER_CERT* pSignerCert,
        SIGNER_SIGNATURE_INFO* pSignatureInfo,
        IntPtr pProviderInfo,
        SignerSignTimeStampFlags dwTimestampFlags,
        byte* pszTimestampAlgorithmOid,
        char* pwszHttpTimeStamp,
        IntPtr psRequest,
        void* pSipData,
        IntPtr* ppSignerContext,
        IntPtr pCryptoPolicy,
        SIGN_INFO* pSignInfo,
        IntPtr pReserved);

    [DllImport("mssign32.dll", CallingConvention = CallingConvention.Winapi)]
    public static extern int SignerFreeSignerContext(IntPtr pSignerContext);

    [DllImport("crypt32.dll", SetLastError = true)]
    public static extern IntPtr CertOpenStore(
        IntPtr lpszStoreProvider,
        CertEncodingType dwEncodingType,
        IntPtr hCryptProv,
        CertOpenStoreFlags dwFlags,
        IntPtr pvPara);

    [DllImport("crypt32.dll", SetLastError = true)]
    public static extern bool CertCloseStore(IntPtr hCertStore, CertCloseStoreFlags dwFlags);

    [DllImport("crypt32.dll", SetLastError = true)]
    public static extern bool CertAddCertificateContextToStore(
        IntPtr hCertStore,
        IntPtr pCertContext,
        uint dwAddDisposition,
        IntPtr ppStoreContext);

    public static uint HashAlgorithmToAlgId(HashAlgorithmName hashAlgorithmName) => hashAlgorithmName.Name switch
    {
        nameof(HashAlgorithmName.SHA1) => 0x00008004,
        nameof(HashAlgorithmName.SHA256) => 0x0000800c,
        nameof(HashAlgorithmName.SHA384) => 0x0000800d,
        nameof(HashAlgorithmName.SHA512) => 0x0000800e,
        _ => throw new NotSupportedException($"Unsupported hash algorithm '{hashAlgorithmName.Name}'.")
    };

    public static ReadOnlySpan<byte> HashAlgorithmToOidAsciiTerminated(HashAlgorithmName hashAlgorithmName)
        => hashAlgorithmName.Name switch
        {
            nameof(HashAlgorithmName.SHA1) => "1.3.14.3.2.26\0"u8,
            nameof(HashAlgorithmName.SHA256) => "2.16.840.1.101.3.4.2.1\0"u8,
            nameof(HashAlgorithmName.SHA384) => "2.16.840.1.101.3.4.2.2\0"u8,
            nameof(HashAlgorithmName.SHA512) => "2.16.840.1.101.3.4.2.3\0"u8,
            _ => throw new NotSupportedException($"Unsupported hash algorithm '{hashAlgorithmName.Name}'.")
        };
}

[StructLayout(LayoutKind.Sequential)]
internal struct BCRYPT_PKCS1_PADDING_INFO
{
    public IntPtr pszAlgId;
}

[Flags]
internal enum SignerSignEx3Flags : uint
{
    NONE = 0x0,
    SPC_EXC_PE_PAGE_HASHES_FLAG = 0x010,
    SPC_INC_PE_PAGE_HASHES_FLAG = 0x100,
    SIGN_CALLBACK_UNDOCUMENTED = 0x400,
    SIG_APPEND = 0x1000
}

internal enum SignerSignTimeStampFlags : uint
{
    None = 0,
    SIGNER_TIMESTAMP_AUTHENTICODE = 1,
    SIGNER_TIMESTAMP_RFC3161 = 2
}

internal enum SignerSignatureInfoAttrChoice : uint
{
    SIGNER_NO_ATTR = 0,
    SIGNER_AUTHCODE_ATTR = 1
}

internal enum SignerCertChoice : uint
{
    SIGNER_CERT_SPC_FILE = 1,
    SIGNER_CERT_STORE = 2,
    SIGNER_CERT_SPC_CHAIN = 3
}

internal enum SignerSubjectInfoUnionChoice : uint
{
    SIGNER_SUBJECT_FILE = 0x01,
    SIGNER_SUBJECT_BLOB = 0x02
}

[Flags]
internal enum SignerCertStoreInfoFlags
{
    SIGNER_CERT_POLICY_STORE = 0x01,
    SIGNER_CERT_POLICY_CHAIN = 0x02,
    SIGNER_CERT_POLICY_CHAIN_NO_ROOT = 0x08
}

[Flags]
internal enum CertOpenStoreFlags : uint
{
    NONE = 0
}

[Flags]
internal enum CertCloseStoreFlags : uint
{
    NONE = 0
}

internal enum CertEncodingType : uint
{
    NONE = 0
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct SIGNER_FILE_INFO
{
    public uint cbSize;
    public char* pwszFileName;
    public IntPtr hFile;

    public SIGNER_FILE_INFO(char* pwszFileName, IntPtr hFile)
    {
        cbSize = (uint)Marshal.SizeOf<SIGNER_FILE_INFO>();
        this.pwszFileName = pwszFileName;
        this.hFile = hFile;
    }
}

[StructLayout(LayoutKind.Explicit)]
internal unsafe struct SIGNER_SUBJECT_INFO_UNION
{
    [FieldOffset(0)]
    public SIGNER_FILE_INFO* file;

    public SIGNER_SUBJECT_INFO_UNION(SIGNER_FILE_INFO* file)
    {
        this.file = file;
    }
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct SIGNER_SUBJECT_INFO
{
    public uint cbSize;
    public uint* pdwIndex;
    public SignerSubjectInfoUnionChoice dwSubjectChoice;
    public SIGNER_SUBJECT_INFO_UNION unionInfo;

    public SIGNER_SUBJECT_INFO(uint* pdwIndex, SignerSubjectInfoUnionChoice dwSubjectChoice, SIGNER_SUBJECT_INFO_UNION unionInfo)
    {
        cbSize = (uint)Marshal.SizeOf<SIGNER_SUBJECT_INFO>();
        this.pdwIndex = pdwIndex;
        this.dwSubjectChoice = dwSubjectChoice;
        this.unionInfo = unionInfo;
    }
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct SIGNER_ATTR_AUTHCODE
{
    public uint cbSize;
    public uint fCommercial;
    public uint fIndividual;
    public char* pwszName;
    public char* pwszInfo;

    public SIGNER_ATTR_AUTHCODE(char* pwszName, char* pwszInfo)
    {
        cbSize = (uint)Marshal.SizeOf<SIGNER_ATTR_AUTHCODE>();
        fCommercial = 0;
        fIndividual = 0;
        this.pwszName = pwszName;
        this.pwszInfo = pwszInfo;
    }
}

[StructLayout(LayoutKind.Explicit)]
internal unsafe struct SIGNER_SIGNATURE_INFO_UNION
{
    [FieldOffset(0)]
    public SIGNER_ATTR_AUTHCODE* pAttrAuthcode;

    public SIGNER_SIGNATURE_INFO_UNION(SIGNER_ATTR_AUTHCODE* pAttrAuthcode)
    {
        this.pAttrAuthcode = pAttrAuthcode;
    }
}

[StructLayout(LayoutKind.Sequential)]
internal struct SIGNER_SIGNATURE_INFO
{
    public uint cbSize;
    public uint algidHash;
    public SignerSignatureInfoAttrChoice dwAttrChoice;
    public SIGNER_SIGNATURE_INFO_UNION attrAuthUnion;
    public IntPtr psAuthenticated;
    public IntPtr psUnauthenticated;

    public SIGNER_SIGNATURE_INFO(
        uint algidHash,
        SignerSignatureInfoAttrChoice dwAttrChoice,
        SIGNER_SIGNATURE_INFO_UNION attrAuthUnion)
    {
        cbSize = (uint)Marshal.SizeOf<SIGNER_SIGNATURE_INFO>();
        this.algidHash = algidHash;
        this.dwAttrChoice = dwAttrChoice;
        this.attrAuthUnion = attrAuthUnion;
        psAuthenticated = IntPtr.Zero;
        psUnauthenticated = IntPtr.Zero;
    }
}

[StructLayout(LayoutKind.Sequential)]
internal struct SIGNER_CERT_STORE_INFO
{
    public uint cbSize;
    public IntPtr pSigningCert;
    public SignerCertStoreInfoFlags dwCertPolicy;
    public IntPtr hCertStore;

    public SIGNER_CERT_STORE_INFO(IntPtr pSigningCert, SignerCertStoreInfoFlags dwCertPolicy, IntPtr hCertStore)
    {
        cbSize = (uint)Marshal.SizeOf<SIGNER_CERT_STORE_INFO>();
        this.pSigningCert = pSigningCert;
        this.dwCertPolicy = dwCertPolicy;
        this.hCertStore = hCertStore;
    }
}

[StructLayout(LayoutKind.Explicit)]
internal unsafe struct SIGNER_CERT_UNION
{
    [FieldOffset(0)]
    public SIGNER_CERT_STORE_INFO* pSpcChainInfo;

    public SIGNER_CERT_UNION(SIGNER_CERT_STORE_INFO* certStoreInfo)
    {
        pSpcChainInfo = certStoreInfo;
    }
}

[StructLayout(LayoutKind.Sequential)]
internal struct SIGNER_CERT
{
    public uint cbSize;
    public SignerCertChoice dwCertChoice;
    public SIGNER_CERT_UNION union;
    public IntPtr hwnd;

    public SIGNER_CERT(SignerCertChoice dwCertChoice, SIGNER_CERT_UNION union)
    {
        this.dwCertChoice = dwCertChoice;
        this.union = union;
        hwnd = IntPtr.Zero;
        cbSize = (uint)Marshal.SizeOf<SIGNER_CERT>();
    }
}

[StructLayout(LayoutKind.Sequential)]
internal struct SIGN_INFO
{
    public uint cbSize;
    public IntPtr callback;
    public IntPtr pvOpaque;

    public SIGN_INFO(IntPtr callback)
    {
        cbSize = (uint)Marshal.SizeOf<SIGN_INFO>();
        this.callback = callback;
        pvOpaque = IntPtr.Zero;
    }
}

[StructLayout(LayoutKind.Sequential)]
internal struct CRYPTOAPI_BLOB
{
    public uint cbData;
    public IntPtr pbData;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct SIGNER_SIGN_EX3_PARAMS
{
    public SignerSignEx3Flags dwFlags;
    public SIGNER_SUBJECT_INFO* pSubjectInfo;
    public SIGNER_CERT* pSignerCert;
    public SIGNER_SIGNATURE_INFO* pSignatureInfo;
    public IntPtr pProviderInfo;
    public SignerSignTimeStampFlags dwTimestampFlags;
    public byte* pszTimestampAlgorithmOid;
    public char* pwszHttpTimeStamp;
    public IntPtr psRequest;
    public SIGN_INFO* pSignCallBack;
    public IntPtr* ppSignerContext;
    public IntPtr pCryptoPolicy;
    public IntPtr pReserved;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct APPX_SIP_CLIENT_DATA
{
    public SIGNER_SIGN_EX3_PARAMS* pSignerParams;
    public IntPtr pAppxSipState;
}

[UnmanagedFunctionPointer(CallingConvention.Winapi)]
internal delegate int SignCallback(
    [In] IntPtr pCertContext,
    [In] IntPtr pvExtra,
    [In] uint algId,
    [In, MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 4)] byte[] pDigestToSign,
    [In] uint dwDigestToSign,
    [In, Out] ref CRYPTOAPI_BLOB blob);
