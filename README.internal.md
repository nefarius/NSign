# nsign (internal)

Silent Authenticode signer for the SafeNet Authentication Client hardware token. Not published; private automation only.

`nsign` is a **signtool-compatible drop-in**. It injects the token PIN into the SafeNet CNG KSP (`NCRYPT_PIN_PROPERTY` + `NCRYPT_SILENT_FLAG`) and signs via `SignerSignEx3`, so the SafeNet PIN dialog never appears. PIN change / expiry dialogs are intentionally not automated.

## Setup (once)

1. Publish:

   ```powershell
   dotnet publish .\src\nsign\nsign.csproj -c Release -o .\artifacts\nsign
   ```

2. Store the token PIN in the **current user's** Credential Manager (DPAPI):

   ```powershell
   .\artifacts\nsign\nsign.exe set-pin
   ```

   Target name: `SafeNet:CodeSign`. Re-run after you change the PIN in SafeNet Authentication Client / your password manager.

3. Confirm the EV cert is visible:

   ```powershell
   .\artifacts\nsign\nsign.exe list-certs
   ```

   Expected provider: `SafeNet Smart Card Key Storage Provider`. Default thumbprint: `FF0CCF318FD8C14775023A0B52C28FFCCA59D7F7`.

   A live `nsign sign` against a throwaway copy (then `nsign verify` / `signtool verify /pa /v`) is the remaining hardware check after `set-pin`. The PIN dialog must not appear; PIN-change/expiry dialogs stay manual.

## SignRelay integration

No SignRelay source changes. Point the agent at `nsign.exe` and run it in-process as the token-owning user.

In the agent config (`SignRelayAgent` / `%ProgramData%` machine config / environment):

| Setting | Value |
| --- | --- |
| `SignRelayAgent__SignToolPath` | Full path to `nsign.exe` |
| `SignRelayAgent__SigningExecution` | `SameProcess` |
| `SignRelayAgent__CertificateThumbprint` | `FF0CCF318FD8C14775023A0B52C28FFCCA59D7F7` (or omit and use subject) |
| `SignRelayAgent__CertificateSubjectName` | `Nefarius Software Solutions e.U.` |
| `SignRelayAgent__TimestampServerUrl` | `http://timestamp.digicert.com` (default) |

**Service account:** the Agent Windows service must run as the same user who owns the token, the `CurrentUser\My` cert, and the `SafeNet:CodeSign` credential. `LocalSystem` cannot see that vault or the user cert store.

The agent already emits:

```
sign /v /fd sha256 [/sha1 <thumb>] [/n <subject>] [/tr <url> /td sha256] <file>
```

`nsign` accepts that argv (`/` or `-` prefixes). Unknown extra flags are ignored.

Smoke-test the exact SignRelay shape:

```powershell
.\artifacts\nsign\nsign.exe sign /v /fd sha256 /n "Nefarius Software Solutions e.U." /tr http://timestamp.digicert.com /td sha256 C:\Temp\sample.exe
```

Exit code `0` means success. The agent only inspects the exit code.

## Direct usage

```powershell
nsign sign /sha1 FF0CCF318FD8C14775023A0B52C28FFCCA59D7F7 file1.dll file2.sys
nsign verify file1.dll
```

PIN is unlocked once per process and reused for every file on the command line.

## Fallback if Credential Manager is the wrong isolation

If the agent must run as a different account than the desktop user, store the PIN with machine-scoped DPAPI in a file readable only by that service account. That path is not implemented; prefer running the service as the token owner.
