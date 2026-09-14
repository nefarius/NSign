using System.Text;
using NSign.Cli;

Console.OutputEncoding = Encoding.UTF8;
Console.InputEncoding = Encoding.UTF8;

return await Root.Build()
    .Parse(SignToolArgNormalizer.Normalize(args))
    .InvokeAsync()
    .ConfigureAwait(false);
