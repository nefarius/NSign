namespace NSign;

internal static class Defaults
{
    public const string DefaultThumbprint = "FF0CCF318FD8C14775023A0B52C28FFCCA59D7F7";
    public const string DefaultTimestampUrl = "http://timestamp.digicert.com";
    public const string CredentialTarget = "SafeNet:CodeSign";
    public const string SafeNetKsp = "SafeNet Smart Card Key Storage Provider";
    public const string CodeSigningEku = "1.3.6.1.5.5.7.3.3";
}

internal static class ExitCodes
{
    public const int Success = 0;
    public const int Failure = 1;
    public const int InvalidArguments = 2;
}
