using System.CommandLine;
using System.Diagnostics;
using NSign.Signing;

namespace NSign.Cli;

internal static class VerifyCommand
{
    private static readonly TimeSpan VerifyTimeout = TimeSpan.FromMinutes(2);

    public static Command Build()
    {
        var files = new Argument<List<string>>("files")
        {
            Description = "Signed files to verify.",
            Arity = ArgumentArity.OneOrMore
        };

        var cmd = new Command("verify", "Verify Authenticode signatures via signtool verify /pa /v.")
        {
            files
        };
        cmd.SetAction(parseResult =>
        {
            if (!SignToolLocator.TryFind(out var signtool))
            {
                Console.Error.WriteLine("signtool.exe not found. Install the Windows SDK or add it to PATH.");
                return ExitCodes.Failure;
            }

            var paths = parseResult.GetValue(files) ?? [];
            var overall = ExitCodes.Success;
            foreach (var file in paths)
            {
                if (!File.Exists(file))
                {
                    Console.Error.WriteLine($"File not found: {file}");
                    overall = ExitCodes.InvalidArguments;
                    continue;
                }

                var psi = new ProcessStartInfo(signtool)
                {
                    ArgumentList = { "verify", "/pa", "/v", file },
                    UseShellExecute = false
                };
                using var proc = Process.Start(psi);
                if (proc is null)
                {
                    Console.Error.WriteLine("Failed to start signtool.");
                    return ExitCodes.Failure;
                }

                if (!proc.WaitForExit(VerifyTimeout))
                {
                    try
                    {
                        proc.Kill(entireProcessTree: true);
                    }
                    catch (InvalidOperationException)
                    {
                    }

                    Console.Error.WriteLine($"signtool verify timed out after {VerifyTimeout.TotalSeconds:0}s: {file}");
                    return ExitCodes.Failure;
                }

                if (proc.ExitCode != 0)
                    overall = ExitCodes.Failure;
            }

            return overall;
        });
        return cmd;
    }
}
