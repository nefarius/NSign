using System.CommandLine;

namespace NSign.Cli;

internal static class Root
{
    public static RootCommand Build()
    {
        var root = new RootCommand(
            "Silent Authenticode signer for a SafeNet Authentication Client hardware token.");
        root.Subcommands.Add(SignCommand.Build());
        root.Subcommands.Add(PinCommand.Build());
        root.Subcommands.Add(ListCertsCommand.Build());
        root.Subcommands.Add(VerifyCommand.Build());
        return root;
    }
}
