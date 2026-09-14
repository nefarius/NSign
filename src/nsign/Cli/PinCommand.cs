using System.CommandLine;
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
            var pin = ReadMasked();
            Console.WriteLine();

            if (string.IsNullOrEmpty(pin))
            {
                Console.Error.WriteLine("PIN was empty; nothing stored.");
                return ExitCodes.InvalidArguments;
            }

            try
            {
                CredentialStore.WritePin(pin);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Failed to store PIN: {ex.GetType().Name}");
                return ExitCodes.Failure;
            }
            finally
            {
                pin = string.Empty;
            }

            Console.WriteLine($"PIN stored in Credential Manager as '{Defaults.CredentialTarget}'.");
            return ExitCodes.Success;
        });
        return cmd;
    }

    private static string ReadMasked()
    {
        var buffer = new System.Text.StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
                break;
            if (key.Key == ConsoleKey.Backspace)
            {
                if (buffer.Length > 0)
                    buffer.Length--;
                continue;
            }

            if (key.KeyChar == '\0')
                continue;

            buffer.Append(key.KeyChar);
        }

        return buffer.ToString();
    }
}
