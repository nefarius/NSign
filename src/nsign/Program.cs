using System.Text;
using NSign;
using NSign.Cli;

if (!OperatingSystem.IsWindows())
{
    Console.Error.WriteLine("nsign requires Windows (x64). SafeNet CNG and Credential Manager APIs are not available on this OS.");
    return ExitCodes.Failure;
}

Console.OutputEncoding = Encoding.UTF8;
Console.InputEncoding = Encoding.UTF8;

return await Root.Build()
    .Parse(SignToolArgNormalizer.Normalize(args))
    .InvokeAsync()
    .ConfigureAwait(false);
