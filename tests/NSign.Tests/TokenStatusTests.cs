using NSign.Signing;

namespace NSign.Tests;

public sealed class TokenStatusTests
{
    [Fact]
    public void Describe_KnownStatuses_AreOperatorActionable()
    {
        Assert.Equal("Success", TokenStatus.Describe(TokenStatus.S_OK));
        Assert.Contains("PIN change", TokenStatus.Describe(TokenStatus.NTE_SILENT_CONTEXT));
        Assert.Contains("set-pin", TokenStatus.Describe(TokenStatus.NTE_INCORRECT_PASSWORD));
        Assert.Contains("blocked", TokenStatus.Describe(TokenStatus.SCARD_W_CHV_BLOCKED), StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Token not present", TokenStatus.Describe(TokenStatus.SCARD_E_NO_SMARTCARD));
        Assert.Contains("reader", TokenStatus.Describe(TokenStatus.SCARD_E_NO_READERS_AVAILABLE), StringComparison.OrdinalIgnoreCase);
        Assert.Contains("private key", TokenStatus.Describe(TokenStatus.NTE_BAD_KEYSET), StringComparison.OrdinalIgnoreCase);
        Assert.Contains("cancelled", TokenStatus.Describe(TokenStatus.ERROR_CANCELLED), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Describe_UnknownStatus_IncludesHex()
    {
        const int unknown = unchecked((int)0xDEADBEEF);
        var message = TokenStatus.Describe(unknown);
        Assert.Contains("0xDEADBEEF", message, StringComparison.OrdinalIgnoreCase);
    }
}
