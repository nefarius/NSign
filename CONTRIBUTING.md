# Contributing

## Branching

Do not land work directly on `master`. Open a `feat/…` or `fix/…` branch and a pull request.

## Prerequisites

- Windows x64
- [.NET SDK 10.x](https://dotnet.microsoft.com/download/dotnet/10.0) (see `global.json`)
- Windows SDK only if you need `nsign verify`

## Build and test

```powershell
dotnet restore nsign.sln
dotnet format nsign.sln --verify-no-changes
dotnet build nsign.sln -c Release --no-restore
dotnet test nsign.sln -c Release --no-build
dotnet pack .\src\nsign\nsign.csproj -c Release --no-build -o .\artifacts\nupkg
./scripts/Verify-Package.ps1 -PackageDirectory ./artifacts/nupkg
```

Hosted CI runs these hardware-independent tests. Do not add tests that require a connected SafeNet token to the default suite.

## Hardware checks

Physical token signing stays a manual operator check:

1. `nsign set-pin`
2. `nsign list-certs`
3. `nsign sign /v /fd sha256 /sha1 <thumbprint> /tr http://timestamp.digicert.com /td sha256 <file>`
4. `nsign verify <file>`

## Style

The repository uses `.editorconfig`, nullable reference types, and warnings-as-errors. Prefer small, focused changes that keep the `signtool sign` argv contract intact.
