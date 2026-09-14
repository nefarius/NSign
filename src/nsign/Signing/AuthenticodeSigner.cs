using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace NSign.Signing;

internal sealed class AuthenticodeSigner : IDisposable
{
    private readonly SafeNetKey _key;
    private readonly HashAlgorithmName _fileDigest;
    private readonly string? _timestampUrl;
    private readonly HashAlgorithmName _timestampDigest;
    private readonly bool _append;
    private readonly string _description;
    private readonly string _descriptionUrl;
    private readonly MemoryCertificateStore _store;
    private readonly X509Chain _chain;
    private readonly SignCallback _signCallback;

    public AuthenticodeSigner(
        SafeNetKey key,
        HashAlgorithmName fileDigest,
        string? timestampUrl,
        HashAlgorithmName timestampDigest,
        bool append,
        string? description,
        string? descriptionUrl)
    {
        _key = key;
        _fileDigest = fileDigest;
        _timestampUrl = string.IsNullOrWhiteSpace(timestampUrl) ? null : timestampUrl;
        _timestampDigest = timestampDigest;
        _append = append;
        _description = description ?? "";
        _descriptionUrl = descriptionUrl ?? "";
        _store = MemoryCertificateStore.Create();
        _chain = new X509Chain
        {
            ChainPolicy =
            {
                VerificationFlags = X509VerificationFlags.AllFlags
            }
        };
        AddExtraStore(StoreName.CertificateAuthority, StoreLocation.CurrentUser);
        AddExtraStore(StoreName.CertificateAuthority, StoreLocation.LocalMachine);

        _chain.Build(key.Certificate);
        for (var i = 0; i < _chain.ChainElements.Count; i++)
            _store.Add(_chain.ChainElements[i].Certificate);

        _signCallback = SignCallback;
    }

    public unsafe int SignFile(string path)
    {
        var flags = SignerSignEx3Flags.SIGN_CALLBACK_UNDOCUMENTED;
        if (_append)
            flags |= SignerSignEx3Flags.SIG_APPEND;

        SignerSignTimeStampFlags timeStampFlags = SignerSignTimeStampFlags.None;
        ReadOnlySpan<byte> timestampOid = default;
        string? timestampUrl = null;
        if (_timestampUrl is not null)
        {
            timeStampFlags = SignerSignTimeStampFlags.SIGNER_TIMESTAMP_RFC3161;
            timestampOid = Native.HashAlgorithmToOidAsciiTerminated(_timestampDigest);
            timestampUrl = _timestampUrl;
        }

        var sipKind = GetSipKind(path);

        fixed (byte* pTimestampAlgorithm = timestampOid)
        fixed (char* pTimestampUrl = timestampUrl)
        fixed (char* pPath = path)
        fixed (char* pDescription = _description)
        fixed (char* pDescriptionUrl = _descriptionUrl)
        {
            var fileInfo = new SIGNER_FILE_INFO(pPath, IntPtr.Zero);
            var subjectIndex = 0u;
            var subjectUnion = new SIGNER_SUBJECT_INFO_UNION(&fileInfo);
            var subjectInfo = new SIGNER_SUBJECT_INFO(&subjectIndex, SignerSubjectInfoUnionChoice.SIGNER_SUBJECT_FILE, subjectUnion);
            var authCode = new SIGNER_ATTR_AUTHCODE(pDescription, pDescriptionUrl);
            var storeInfo = new SIGNER_CERT_STORE_INFO(
                _key.Certificate.Handle,
                SignerCertStoreInfoFlags.SIGNER_CERT_POLICY_CHAIN,
                _store.Handle);
            var signerCert = new SIGNER_CERT(SignerCertChoice.SIGNER_CERT_STORE, new SIGNER_CERT_UNION(&storeInfo));
            var signatureInfo = new SIGNER_SIGNATURE_INFO(
                Native.HashAlgorithmToAlgId(_fileDigest),
                SignerSignatureInfoAttrChoice.SIGNER_AUTHCODE_ATTR,
                new SIGNER_SIGNATURE_INFO_UNION(&authCode));
            var callbackPtr = Marshal.GetFunctionPointerForDelegate(_signCallback);
            var signInfo = new SIGN_INFO(callbackPtr);

            void* sipData = null;
            var context = IntPtr.Zero;
            APPX_SIP_CLIENT_DATA clientData = default;
            SIGNER_SIGN_EX3_PARAMS appxParams = default;

            if (sipKind == SipKind.Appx)
            {
                clientData.pSignerParams = &appxParams;
                sipData = &clientData;
                flags &= ~SignerSignEx3Flags.SPC_INC_PE_PAGE_HASHES_FLAG;
                flags |= SignerSignEx3Flags.SPC_EXC_PE_PAGE_HASHES_FLAG;
                appxParams.dwFlags = flags;
                appxParams.dwTimestampFlags = timeStampFlags;
                appxParams.pSubjectInfo = &subjectInfo;
                appxParams.pSignerCert = &signerCert;
                appxParams.pSignatureInfo = &signatureInfo;
                appxParams.ppSignerContext = &context;
                appxParams.pwszHttpTimeStamp = pTimestampUrl;
                appxParams.pszTimestampAlgorithmOid = pTimestampAlgorithm;
                appxParams.pSignCallBack = &signInfo;
            }

            var result = Native.SignerSignEx3(
                flags,
                &subjectInfo,
                &signerCert,
                &signatureInfo,
                IntPtr.Zero,
                timeStampFlags,
                pTimestampAlgorithm,
                pTimestampUrl,
                IntPtr.Zero,
                sipData,
                &context,
                IntPtr.Zero,
                &signInfo,
                IntPtr.Zero);

            if (result == 0 && context != IntPtr.Zero)
                Native.SignerFreeSignerContext(context);

            if (result == 0 && sipKind == SipKind.Appx && clientData.pAppxSipState != IntPtr.Zero)
                Marshal.Release(clientData.pAppxSipState);

            return result;
        }
    }

    public void Dispose()
    {
        _chain.Dispose();
        _store.Dispose();
    }

    private int SignCallback(
        IntPtr pCertContext,
        IntPtr pvExtra,
        uint algId,
        byte[] pDigestToSign,
        uint dwDigestToSign,
        ref CRYPTOAPI_BLOB blob)
    {
        try
        {
            var signature = _key.SignHash(pDigestToSign, _fileDigest);
            var resultPtr = Marshal.AllocHGlobal(signature.Length);
            Marshal.Copy(signature, 0, resultPtr, signature.Length);
            blob.pbData = resultPtr;
            blob.cbData = (uint)signature.Length;
            return 0;
        }
        catch (TokenException ex)
        {
            return ex.HResult;
        }
        catch (CryptographicException ex)
        {
            return ex.HResult;
        }
    }

    private void AddExtraStore(StoreName name, StoreLocation location)
    {
        try
        {
            using var extra = new X509Store(name, location);
            extra.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            _chain.ChainPolicy.ExtraStore.AddRange(extra.Certificates);
        }
        catch (CryptographicException)
        {
        }
    }

    private static SipKind GetSipKind(string path)
    {
        var ext = Path.GetExtension(path);
        if (ext.Equals(".appx", StringComparison.OrdinalIgnoreCase)
            || ext.Equals(".appxbundle", StringComparison.OrdinalIgnoreCase)
            || ext.Equals(".msix", StringComparison.OrdinalIgnoreCase)
            || ext.Equals(".msixbundle", StringComparison.OrdinalIgnoreCase)
            || ext.Equals(".eappx", StringComparison.OrdinalIgnoreCase)
            || ext.Equals(".eappxbundle", StringComparison.OrdinalIgnoreCase)
            || ext.Equals(".emsix", StringComparison.OrdinalIgnoreCase)
            || ext.Equals(".emsixbundle", StringComparison.OrdinalIgnoreCase))
        {
            return SipKind.Appx;
        }

        return SipKind.None;
    }

    private enum SipKind
    {
        None,
        Appx
    }
}
