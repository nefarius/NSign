namespace NSign.Signing;

internal static class SignToolLocator
{
    public static bool TryFind(out string path)
    {
        path = "";
        var onPath = FindOnPath("signtool.exe");
        if (onPath is not null)
        {
            path = onPath;
            return true;
        }

        var kits = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Windows Kits", "10", "bin"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows Kits", "10", "bin")
        };

        var versions = new List<(Version Ver, string File)>();
        foreach (var bin in kits)
        {
            if (!Directory.Exists(bin))
                continue;
            foreach (var dir in Directory.GetDirectories(bin))
            {
                if (!Version.TryParse(Path.GetFileName(dir), out var ver))
                    continue;
                var candidate = Path.Combine(dir, "x64", "signtool.exe");
                if (File.Exists(candidate))
                    versions.Add((ver, candidate));
            }
        }

        if (versions.Count == 0)
            return false;

        path = versions.OrderByDescending(v => v.Ver).First().File;
        return true;
    }

    private static string? FindOnPath(string fileName)
    {
        var pathVar = Environment.GetEnvironmentVariable("PATH");
        if (string.IsNullOrEmpty(pathVar))
            return null;

        foreach (var raw in pathVar.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            try
            {
                var full = Path.Combine(raw.Trim().Trim('"'), fileName);
                if (File.Exists(full))
                    return Path.GetFullPath(full);
            }
            catch (ArgumentException)
            {
            }
            catch (PathTooLongException)
            {
            }
        }

        return null;
    }
}
