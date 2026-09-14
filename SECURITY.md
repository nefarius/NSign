# Security policy

## Supported versions

Use the latest tagged release of `Nefarius.Tools.NSign`. Older versions are not maintained.

## Reporting a vulnerability

This tool stores a hardware-token PIN and performs Authenticode signing. Please **do not** file public issues for vulnerabilities that could expose a PIN, private-key material, or a way to sign arbitrary files.

Use [GitHub private vulnerability reporting](https://github.com/nefarius/NSign/security/advisories/new) and include:

- The affected version or commit
- A clear reproduction
- Impact (PIN disclosure, unauthorized signing, trust bypass, etc.)

Please give a reasonable window for a fix and coordinated disclosure before publishing details. Use the public issue tracker only for non-sensitive defects.

## Threat model

`nsign` is a same-user Windows signing helper, not a sandbox.

- The PIN is stored as a generic Windows Credential Manager secret with `CRED_PERSIST_LOCAL_MACHINE`. It is available to later logon sessions of **the same Windows user on this computer**, and to any process running as that user. Other Windows users cannot read it.
- A Windows service that runs as the token owner can see that user's certificate store and PIN vault. That is a privilege trade-off.
- Silent signing fails when the token requires UI (PIN change or expiry). Those states stay a manual operator task.
- Hosted CI does not exercise a physical SafeNet token. Hardware-path defects should be reported with SafeNet Authentication Client version and token connection details.
