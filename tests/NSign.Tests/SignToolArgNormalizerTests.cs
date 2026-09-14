using NSign.Cli;

namespace NSign.Tests;

public sealed class SignToolArgNormalizerTests
{
    [Fact]
    public void Empty_ReturnsSameInstance()
    {
        var args = Array.Empty<string>();
        Assert.Same(args, SignToolArgNormalizer.Normalize(args));
    }

    [Fact]
    public void RewritesSlashFlags_AndKeepsOperands()
    {
        var normalized = SignToolArgNormalizer.Normalize(
            ["sign", "/v", "/fd", "sha256", "/sha1", "ABC", @"C:\Temp\app.exe"]);

        Assert.Equal(["sign", "--v", "--fd", "sha256", "--sha1", "ABC", @"C:\Temp\app.exe"], normalized);
    }

    [Fact]
    public void SplitsCombinedColonForm()
    {
        var normalized = SignToolArgNormalizer.Normalize(["sign", "/fd:sha256", "-tr:http://timestamp.example"]);
        Assert.Equal(["sign", "--fd", "sha256", "--tr", "http://timestamp.example"], normalized);
    }

    [Fact]
    public void LeavesPosixAndWindowsPathsAlone()
    {
        var normalized = SignToolArgNormalizer.Normalize(["sign", "/tmp/app.exe", @"D:\out\app.exe"]);
        Assert.Equal(["sign", "/tmp/app.exe", @"D:\out\app.exe"], normalized);
    }

    [Fact]
    public void LeavesAlreadyLongOptionsAlone()
    {
        var normalized = SignToolArgNormalizer.Normalize(["sign", "--verbose", "--fd", "sha256"]);
        Assert.Equal(["sign", "--verbose", "--fd", "sha256"], normalized);
    }

    [Theory]
    [InlineData("/v", true)]
    [InlineData("-fd", true)]
    [InlineData("--sha1", true)]
    [InlineData("/tmp/app.exe", false)]
    [InlineData(@"C:\Temp\app.exe", false)]
    [InlineData("sample.exe", false)]
    public void IsFlagToken_DistinguishesFlagsFromPaths(string token, bool expected)
    {
        Assert.Equal(expected, SignToolArgNormalizer.IsFlagToken(token));
    }
}
