namespace NSign.Cli;

/// <summary>
/// Rewrites signtool-style <c>/flag</c> tokens to <c>--flag</c> so System.CommandLine
/// can parse the argv shape SignRelay emits.
/// </summary>
internal static class SignToolArgNormalizer
{
    public static string[] Normalize(string[] args)
    {
        if (args.Length == 0)
            return args;

        var result = new List<string>(args.Length + 4);
        foreach (var arg in args)
        {
            if (TrySplitCombined(arg, out var flag, out var value))
            {
                result.Add(flag);
                result.Add(value);
                continue;
            }

            if (TryRewriteFlag(arg, out var rewritten))
            {
                result.Add(rewritten);
                continue;
            }

            result.Add(arg);
        }

        return result.ToArray();
    }

    private static bool TrySplitCombined(string arg, out string flag, out string value)
    {
        flag = "";
        value = "";

        if (!LooksLikeFlag(arg))
            return false;

        var slash = arg.StartsWith('/') ? 1 : arg.StartsWith('-') && !arg.StartsWith("--") ? 1 : 0;
        if (slash == 0)
            return false;

        var colon = arg.IndexOf(':', StringComparison.Ordinal);
        if (colon <= slash)
            return false;

        var name = arg[(slash)..colon];
        if (name.Contains('/') || name.Contains('\\'))
            return false;

        flag = "--" + name.TrimStart('-');
        value = arg[(colon + 1)..];
        return value.Length > 0;
    }

    private static bool TryRewriteFlag(string arg, out string rewritten)
    {
        rewritten = arg;
        if (!arg.StartsWith('/') || arg.Length < 2)
            return false;

        // POSIX absolute paths such as /tmp/foo.exe keep their slashes; skip those.
        if (arg.IndexOf('/', 1) >= 0 || arg.Contains('\\'))
            return false;

        if (!char.IsLetter(arg[1]))
            return false;

        rewritten = "--" + arg[1..];
        return true;
    }

    internal static bool IsFlagToken(string token)
    {
        if (token.Contains('\\', StringComparison.Ordinal))
            return false;
        if (token.StartsWith("--", StringComparison.Ordinal)
            && token.Length > 2
            && char.IsLetter(token[2])
            && token.IndexOf('/', 2) < 0)
            return true;
        return token.Length >= 2
               && token[0] is '-' or '/'
               && char.IsLetter(token[1])
               && token.IndexOf('/', 1) < 0;
    }

    private static bool LooksLikeFlag(string arg)
        => arg.Length >= 2 && (arg[0] is '/' or '-') && char.IsLetter(arg[1]);
}
