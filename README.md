# nsign

Silent Authenticode signer for a SafeNet Authentication Client hardware token. Drop-in replacement for the Windows SDK `signtool sign` argv that SignRelay (and similar agents) already emit.

`nsign` injects the token PIN into the SafeNet CNG KSP (`NCRYPT_PIN_PROPERTY`) and performs private-key operations with `NCRYPT_SILENT_FLAG`, then signs via `SignerSignEx3`. The SafeNet PIN dialog is not shown. PIN-change and PIN-expiry dialogs are **not** automated; those stay a manual operator task.

## Features

- `signtool`-compatible `sign` verb (`/` or `-` prefixes).
- PIN stored in the current user's Windows Credential Manager (DPAPI).
- One process unlocks the token once and signs every file on the command line.
- RFC3161 timestamping (`/tr`, `/td`).
- `list-certs` and `verify` helpers.

## Limitations

- Windows x64 only. The agent/token path is a Windows smart-card KSP.
- Requires SafeNet Authentication Client and a connected token (USB, USB-over-IP, etc.).
- Unknown `signtool` flags are **rejected** (nonzero exit). Supported flags are listed under [CLI](#cli).
- Credential Manager generic credentials are readable by **any process running as the same Windows user**. This is not isolation from same-user malware.
- Running a signing service as the token-owning interactive user lets the service see that user's cert store and PIN vault. That is a privilege trade-off, not a hardening step.
- `NCRYPT_SILENT_FLAG` is applied on `NCryptSignHash`, not on the PIN `SetProperty` call. If the token requires UI (PIN change / expiry), the silent sign fails instead of prompting.

## Supported systems

| Component | Supported |
| --- | --- |
| OS | Windows 10/11, **x64** |
| SDK (source build / pack / standalone publish) | [.NET SDK 10.x](https://dotnet.microsoft.com/download/dotnet/10.0) (project includes `net10.0`) |
| SDK (`dotnet tool` install / update) | .NET SDK 8.x, 9.x, or 10.x |
| Runtime (global/local tool) | Matching .NET 8, 9, or 10 **runtime** on Windows x64 |
| Token stack | SafeNet Authentication Client (tested with 10.9.x) + SafeNet Smart Card Key Storage Provider |
| Timestamp | RFC3161 HTTP(S) timestamp servers |

Other architectures, non-Windows hosts, and non-SafeNet KSPs are out of scope. `dotnet tool` is an SDK feature; a runtime-only install cannot install or update the package.

## Installation

### .NET tool

```powershell
dotnet tool install -g Nefarius.Tools.NSign
```

This puts the `nsign` shim on `PATH` (typically `%USERPROFILE%\.dotnet\tools\nsign.exe`). Requires a .NET 8, 9, or 10 **SDK** on Windows x64.

```powershell
dotnet tool update -g Nefarius.Tools.NSign
dotnet tool uninstall -g Nefarius.Tools.NSign
```

Local (repo-scoped) install:

```powershell
dotnet new tool-manifest
dotnet tool install Nefarius.Tools.NSign
```

### Local package (before nuget.org)

```powershell
dotnet pack .\src\nsign\nsign.csproj -c Release -o .\artifacts\nupkg
dotnet tool install -g --add-source .\artifacts\nupkg Nefarius.Tools.NSign
```

### Standalone exe

Self-contained `win-x64` single-file publish for hosts that should not depend on a shared .NET runtime (SignRelay agents, air-gapped machines):

```powershell
dotnet publish .\src\nsign\nsign.csproj -c Release -f net10.0 -p:PublishProfile=Standalone-win-x64
```

Output: `.\artifacts\nsign\nsign.exe`.

## Quick start

1. Install the tool or publish the standalone exe (see [Installation](#installation)).
2. Store the token PIN in the **current user's** Credential Manager:

   ```powershell
   nsign set-pin
   ```

   Target name: `SafeNet:CodeSign`. Re-run after you change the PIN in SafeNet Authentication Client or your password manager.

3. Confirm the signing certificate is visible:

   ```powershell
   nsign list-certs
   ```

   The private-key provider should be `SafeNet Smart Card Key Storage Provider`.

4. Sign (pass `/sha1` or `/n`; there is no baked-in default certificate):

   ```powershell
   nsign sign /v /fd sha256 /sha1 <thumbprint> /tr http://timestamp.digicert.com /td sha256 C:\Temp\sample.exe
   ```

5. Verify:

   ```powershell
   nsign verify C:\Temp\sample.exe
   ```

   (`verify` shells out to Windows SDK `signtool verify /pa /v`.)

Standalone publish uses `.\artifacts\nsign\nsign.exe` in place of `nsign`.

## SignRelay integration

No SignRelay source changes. Point the agent at `nsign.exe` and run signing in-process.

| Setting | Value |
| --- | --- |
| `SignRelayAgent__SignToolPath` | Full path to `nsign.exe` — either the global-tool shim (`%USERPROFILE%\.dotnet\tools\nsign.exe` for the service account) or the standalone publish output |
| `SignRelayAgent__SigningExecution` | `SameProcess` |
| `SignRelayAgent__CertificateThumbprint` | SHA-1 thumbprint of the token cert (or use subject) |
| `SignRelayAgent__CertificateSubjectName` | Subject substring, if you prefer `/n` |
| `SignRelayAgent__TimestampServerUrl` | RFC3161 URL (SignRelay default is DigiCert) |

A Windows service does not inherit an interactive user's `PATH`. Prefer the full shim or standalone path over a bare `nsign` command name.

The Agent Windows service must run as the **same user** who owns the token, the `CurrentUser\My` certificate, and the `SafeNet:CodeSign` credential. `LocalSystem` cannot see that vault or the user cert store.

That service-as-user choice expands the service's access to the interactive profile. Prefer a dedicated signing account over a daily-driver desktop login when you can.

The agent already emits:

```
sign /v /fd sha256 [/sha1 <thumb>] [/n <subject>] [/tr <url> /td sha256] <file>
```

`nsign` accepts that argv. Exit code `0` is success; the agent only inspects the exit code.

## CLI

| Command | Purpose |
| --- | --- |
| `nsign sign` | Authenticode-sign one or more files |
| `nsign set-pin` | Prompt once (masked) and write Credential Manager |
| `nsign list-certs` | List `CurrentUser\My` code-signing certs and KSP |
| `nsign verify` | `signtool verify /pa /v` wrapper |

`sign` options (each accepts `/x`, `-x`, and `--x` where registered):

| Flag | Meaning |
| --- | --- |
| `/v` | Verbose status |
| `/fd` | File digest (default `sha256`) |
| `/td` | Timestamp digest (default `sha256`) |
| `/sha1` | Certificate thumbprint |
| `/n` | Certificate subject substring |
| `/tr` | RFC3161 timestamp URL (default `http://timestamp.digicert.com`) |
| `/as` | Append signature |
| `/d`, `/du` | Description and description URL |

Either `/sha1` or `/n` is required.

## Build

Prerequisites:

- .NET SDK **10.x** (required to build, pack, and publish because the project targets `net10.0`)
- Windows x64
- Windows SDK (only required for `nsign verify`, which locates `signtool.exe`)

```powershell
dotnet restore nsign.sln
dotnet build nsign.sln -c Release
dotnet pack .\src\nsign\nsign.csproj -c Release -o .\artifacts\nupkg
dotnet publish .\src\nsign\nsign.csproj -c Release -f net10.0 -p:PublishProfile=Standalone-win-x64
```

Package version comes from [MinVer](https://github.com/adamralph/minver) (`v`-prefixed tags). Untagged builds pack as `0.0.0`.

## Security notes

- The PIN never appears on the command line. It is read by `set-pin` and stored as a generic Windows credential.
- Managed strings cannot be reliably wiped. `nsign` keeps the PIN in a disposable `char[]` and zeros that buffer (and the CredWrite blob) after use. This reduces residual copies; it does not make the PIN disappear from process memory.
- Same-user processes can `CredRead` `SafeNet:CodeSign`. Treat the Windows login that runs `nsign` as the security boundary.
- If the token would need UI, silent signing returns a mapped error (wrong/blocked PIN, PIN change required, token missing) and a nonzero exit code.

## Support policy

- Use the issue tracker for defects and concrete improvements to this repository.
- Token hardware, SafeNet Authentication Client versions, USB-over-IP, and certificate issuance are operator concerns.
- Issues without reproduction details or requests outside the documented Windows/SAC scope may be closed.

## License

This project is licensed under the **MIT License** — see [`LICENSE`](LICENSE).

Copyright (c) 2026 Benjamin Höglinger-Stelzer.

Third-party notices: [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md).

## Legal / trademark notes

**Windows**, **.NET**, **Authenticode**, **SafeNet**, and **SafeNet Authentication Client** are trademarks of their respective owners. References here are for identification only.

## Sources and credits

- Authenticode `SignerSignEx3` interop and digest-callback flow: [AzureSignTool](https://github.com/vcsjones/AzureSignTool) (MIT)
- CLI: [System.CommandLine](https://learn.microsoft.com/en-us/dotnet/standard/commandline/) 2.0.11
- Typical consumer: [SignRelay](https://github.com/nefarius/SignRelay) (optional; this repo does not depend on it)
