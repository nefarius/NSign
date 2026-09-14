#pragma warning disable IDE1006 // Win32 status constant names
namespace NSign.Signing;

internal sealed class TokenException : Exception
{
    public TokenException(int status, string message) : base(message)
    {
        HResult = status;
    }
}

internal static class TokenStatus
{
    public const int S_OK = 0;
    public const int NTE_SILENT_CONTEXT = unchecked((int)0x80090022);
    public const int NTE_UI_REQUIRED = unchecked((int)0x8009002E);
    public const int NTE_INCORRECT_PASSWORD = unchecked((int)0x80090033);
    public const int NTE_BAD_KEYSET = unchecked((int)0x80090016);
    public const int SCARD_W_WRONG_CHV = unchecked((int)0x8010006B);
    public const int SCARD_W_CHV_BLOCKED = unchecked((int)0x8010006C);
    public const int SCARD_W_CANCELLED_BY_USER = unchecked((int)0x8010006E);
    public const int SCARD_E_NO_SMARTCARD = unchecked((int)0x8010000C);
    public const int SCARD_E_NO_READERS_AVAILABLE = unchecked((int)0x8010002E);
    public const int SCARD_W_REMOVED_CARD = unchecked((int)0x80100069);
    public const int ERROR_CANCELLED = unchecked((int)0x800704C7);

    public static string Describe(int status) => status switch
    {
        S_OK => "Success",
        NTE_SILENT_CONTEXT or NTE_UI_REQUIRED =>
            "The token required UI (PIN change / expiry). Update the PIN in your password manager, then run nsign set-pin.",
        NTE_INCORRECT_PASSWORD or SCARD_W_WRONG_CHV =>
            "Wrong token PIN. Update Credential Manager with: nsign set-pin",
        SCARD_W_CHV_BLOCKED =>
            "Token PIN is blocked. Unblock it with SafeNet Authentication Client, then run nsign set-pin.",
        SCARD_E_NO_SMARTCARD or SCARD_W_REMOVED_CARD =>
            "Token not present. Check the USB-over-IP connection and SafeNet Authentication Client.",
        SCARD_E_NO_READERS_AVAILABLE =>
            "No smart-card reader. Is SafeNet Authentication Client running and the USB-over-IP token attached?",
        NTE_BAD_KEYSET =>
            "The private key is not available on the SafeNet KSP. Confirm the token is connected.",
        SCARD_W_CANCELLED_BY_USER or ERROR_CANCELLED =>
            "The operation was cancelled.",
        _ => $"Signing failed with status 0x{status:X8}"
    };
}
