using NSign.Credentials;

namespace NSign.Tests;

public sealed class PinSecretTests
{
    [Fact]
    public void ExposesAndZerosPinnedBuffer()
    {
        var chars = new[] { '1', '2', '3', '4' };
        using (var pin = new PinSecret(chars))
        {
            Assert.False(pin.IsEmpty);
            Assert.Equal("1234", new string(pin.Span));
        }

        Assert.All(chars, ch => Assert.Equal('\0', ch));
    }

    [Fact]
    public void EmptyAfterDispose()
    {
        var pin = new PinSecret(['a']);
        pin.Dispose();
        Assert.True(pin.IsEmpty);
        Assert.True(pin.Span.IsEmpty);
    }
}
