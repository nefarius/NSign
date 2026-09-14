using NSign.Cli;
using NSign.Signing;

namespace NSign.Tests;

public sealed class CliParsingTests
{
    [Fact]
    public async Task Sign_WithoutFiles_ReturnsInvalidArguments()
    {
        var exit = await InvokeAsync(["sign"]);
        Assert.Equal(ExitCodes.InvalidArguments, exit);
    }

    [Fact]
    public async Task Sign_UnknownFlag_IsRejected()
    {
        var exit = await InvokeAsync(["sign", "/not-a-real-flag", "app.exe"]);
        Assert.Equal(ExitCodes.InvalidArguments, exit);
    }

    [Fact]
    public void Sign_MissingFile_IsRejectedBeforePinRead()
    {
        var missing = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".exe");
        var exit = SignCommand.Run(new SignOptions
        {
            Files = [missing]
        });
        Assert.Equal(ExitCodes.InvalidArguments, exit);
    }

    [Fact]
    public void Sign_FlagLikeOperand_IsRejected()
    {
        var exit = SignCommand.Run(new SignOptions
        {
            Files = ["/fd"]
        });
        Assert.Equal(ExitCodes.InvalidArguments, exit);
    }

    [Fact]
    public async Task Root_Help_Succeeds()
    {
        var exit = await InvokeAsync(["--help"]);
        Assert.Equal(ExitCodes.Success, exit);
    }

    private static Task<int> InvokeAsync(string[] args)
        => Root.Build().Parse(SignToolArgNormalizer.Normalize(args)).InvokeAsync();
}
