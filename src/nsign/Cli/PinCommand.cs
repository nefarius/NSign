using System.CommandLine;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using NSign.Credentials;

namespace NSign.Cli;

internal static class PinCommand
{
    public static Command Build()
    {
        var cmd = new Command("set-pin", "Store the token PIN in the current user's Credential Manager.");
        cmd.SetAction(_ =>
        {
            Console.Write("Token PIN: ");
            using var pin = ReadMasked();
            Console.WriteLine();

            if (pin.IsEmpty)
            {
                Console.Error.WriteLine("PIN was empty; nothing stored.");
                return ExitCodes.InvalidArguments;
            }

            try
            {
                CredentialStore.WritePin(pin.Span);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Failed to store PIN: {ex.GetType().Name}");
                return ExitCodes.Failure;
            }

            Console.WriteLine($"PIN stored in Credential Manager as '{Defaults.CredentialTarget}'.");
            return ExitCodes.Success;
        });
        return cmd;
    }

    private static PinSecret ReadMasked()
    {
        var buffer = new char[256];
        var length = 0;
        try
        {
            while (true)
            {
                var key = Console.ReadKey(intercept: true);
                if (key.Key == ConsoleKey.Enter)
                    break;
                if (key.Key == ConsoleKey.Backspace)
                {
                    if (length > 0)
                    {
                        length--;
                        buffer[length] = '\0';
                    }
                    continue;
                }

                if (key.KeyChar == '\0')
                    continue;

                if (length >= buffer.Length)
                {
                    var grown = new char[buffer.Length * 2];
                    buffer.AsSpan(0, length).CopyTo(grown);
                    CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(buffer.AsSpan()));
                    buffer = grown;
                }

                buffer[length++] = key.KeyChar;
            }

            var pin = new char[length];
            buffer.AsSpan(0, length).CopyTo(pin);
            return new PinSecret(pin);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(buffer.AsSpan()));
        }
    }
}
