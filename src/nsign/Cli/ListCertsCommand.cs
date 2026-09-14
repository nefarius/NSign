using System.CommandLine;

using NSign.Signing;

namespace NSign.Cli;

internal static class ListCertsCommand
{
    public static Command Build()
    {
        var cmd = new Command("list-certs", "List CurrentUser\\My code-signing certificates and their KSP.");
        cmd.SetAction(_ =>
        {
            var certs = CertificateResolver.ListEligible();
            if (certs.Count == 0)
            {
                Console.WriteLine("No code-signing certificates with a private key in CurrentUser\\My.");
                return ExitCodes.Success;
            }

            foreach (var row in certs)
            {
                Console.WriteLine(row.Thumbprint);
                Console.WriteLine($"  Subject : {row.Subject}");
                Console.WriteLine($"  NotAfter: {row.NotAfter:u}");
                Console.WriteLine($"  Provider: {row.Provider}");
                Console.WriteLine($"  Key     : {row.KeyName}");
                Console.WriteLine();
            }

            return ExitCodes.Success;
        });
        return cmd;
    }
}
