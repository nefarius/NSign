using System.CommandLine;
using System.Security.Cryptography;
using NSign.Credentials;
using NSign.Signing;

namespace NSign.Cli;

internal static class SignCommand
{
    public static Command Build()
    {
        var verbose = new Option<bool>("--v", "-v", "--verbose")
        {
            Description = "Print extra status (signtool /v).",
            DefaultValueFactory = _ => false
        };
        var append = new Option<bool>("--as", "-as")
        {
            Description = "Append the signature (signtool /as).",
            DefaultValueFactory = _ => false
        };
        var fd = new Option<string>("--fd", "-fd")
        {
            Description = "File digest algorithm (signtool /fd).",
            DefaultValueFactory = _ => "sha256"
        };
        var td = new Option<string>("--td", "-td")
        {
            Description = "Timestamp digest algorithm (signtool /td).",
            DefaultValueFactory = _ => "sha256"
        };
        var sha1 = new Option<string?>("--sha1", "-sha1")
        {
            Description = "Certificate SHA-1 thumbprint (signtool /sha1)."
        };
        var subject = new Option<string?>("--n", "-n", "--subject")
        {
            Description = "Certificate subject substring (signtool /n)."
        };
        var timestampUrl = new Option<string?>("--tr", "-tr")
        {
            Description = "RFC3161 timestamp URL (signtool /tr).",
            DefaultValueFactory = _ => Defaults.DefaultTimestampUrl
        };
        var description = new Option<string?>("--d", "-d")
        {
            Description = "Signature description (signtool /d)."
        };
        var descriptionUrl = new Option<string?>("--du", "-du")
        {
            Description = "Signature description URL (signtool /du)."
        };
        var files = new Argument<List<string>>("files")
        {
            Description = "Files to Authenticode-sign.",
            Arity = ArgumentArity.ZeroOrMore
        };

        var cmd = new Command("sign", "Sign files with the SafeNet token (signtool-compatible).")
        {
            verbose,
            append,
            fd,
            td,
            sha1,
            subject,
            timestampUrl,
            description,
            descriptionUrl,
            files
        };
        cmd.TreatUnmatchedTokensAsErrors = true;

        cmd.SetAction((parseResult, ct) =>
        {
            try
            {
                var options = new SignOptions
                {
                    Verbose = parseResult.GetValue(verbose),
                    AppendSignature = parseResult.GetValue(append),
                    Thumbprint = parseResult.GetValue(sha1),
                    Subject = parseResult.GetValue(subject),
                    FileDigest = ParseHash(parseResult.GetValue(fd), "file digest"),
                    TimestampDigest = ParseHash(parseResult.GetValue(td), "timestamp digest"),
                    TimestampUrl = parseResult.GetValue(timestampUrl),
                    Description = parseResult.GetValue(description),
                    DescriptionUrl = parseResult.GetValue(descriptionUrl),
                    Files = parseResult.GetValue(files) ?? []
                };

                return Task.FromResult(Run(options));
            }
            catch (InvalidOperationException ex)
            {
                Console.Error.WriteLine(ex.Message);
                return Task.FromResult(ExitCodes.InvalidArguments);
            }
        });

        return cmd;
    }

    internal static int Run(SignOptions options)
    {
        if (options.Files.Count == 0)
        {
            Console.Error.WriteLine("No files specified.");
            return ExitCodes.InvalidArguments;
        }

        foreach (var file in options.Files)
        {
            if (LooksLikeFlag(file))
            {
                Console.Error.WriteLine($"Unrecognized argument: {file}");
                return ExitCodes.InvalidArguments;
            }

            if (!File.Exists(file))
            {
                Console.Error.WriteLine($"File not found: {file}");
                return ExitCodes.InvalidArguments;
            }
        }

        PinSecret pin;
        try
        {
            if (!CredentialStore.TryReadPin(out pin) || pin.IsEmpty)
            {
                pin.Dispose();
                Console.Error.WriteLine(
                    $"No PIN in Credential Manager (target '{Defaults.CredentialTarget}'). Run: nsign set-pin");
                return ExitCodes.InvalidArguments;
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Failed to read PIN from Credential Manager: {ex.GetType().Name}");
            return ExitCodes.Failure;
        }

        using (pin)
        {
            try
            {
                using var cert = CertificateResolver.Resolve(options.Thumbprint, options.Subject);
                if (options.Verbose)
                    Console.WriteLine($"Using cert {cert.Thumbprint} ({cert.GetNameInfo(System.Security.Cryptography.X509Certificates.X509NameType.SimpleName, false)})");

                using var key = SafeNetKey.Open(cert, pin.Span);
                using var signer = new AuthenticodeSigner(
                    key,
                    options.FileDigest,
                    options.TimestampUrl,
                    options.TimestampDigest,
                    options.AppendSignature,
                    options.Description,
                    options.DescriptionUrl);

                foreach (var file in options.Files)
                {
                    var full = Path.GetFullPath(file);
                    if (options.Verbose)
                        Console.WriteLine($"Signing {full}");

                    var hr = signer.SignFile(full);
                    if (hr != 0)
                    {
                        Console.Error.WriteLine($"Failed to sign {full}: {TokenStatus.Describe(hr)} (0x{hr:X8})");
                        return ExitCodes.Failure;
                    }

                    Console.WriteLine($"Successfully signed: {full}");
                }

                return ExitCodes.Success;
            }
            catch (TokenException ex)
            {
                Console.Error.WriteLine(ex.Message);
                return ExitCodes.Failure;
            }
            catch (InvalidOperationException ex)
            {
                Console.Error.WriteLine(ex.Message);
                return ExitCodes.InvalidArguments;
            }
            catch (CryptographicException ex)
            {
                Console.Error.WriteLine(TokenStatus.Describe(ex.HResult) + $" (0x{ex.HResult:X8})");
                return ExitCodes.Failure;
            }
        }
    }

    private static bool LooksLikeFlag(string token)
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

    private static HashAlgorithmName ParseHash(string? name, string what)
    {
        return (name ?? "sha256").Trim().ToLowerInvariant() switch
        {
            "sha1" or "sha-1" => HashAlgorithmName.SHA1,
            "sha256" or "sha-256" => HashAlgorithmName.SHA256,
            "sha384" or "sha-384" => HashAlgorithmName.SHA384,
            "sha512" or "sha-512" => HashAlgorithmName.SHA512,
            _ => throw new InvalidOperationException($"Unsupported {what} algorithm '{name}'.")
        };
    }
}
